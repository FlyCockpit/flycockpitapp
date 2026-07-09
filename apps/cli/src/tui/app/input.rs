//! Composer key handling: vim mode state machine, history navigation,
//! submit, and the small Ctrl+Shift+{Y,C} helpers shared with the
//! mouse module.

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::tui::composer::{FindSpec, Operator, Register, VimMode};
use crate::tui::history::HistoryEntry;
use crate::tui::textfield::normalize_shift_char;

use super::{App, TranscriptFind};
use crate::daemon::proto::{self, Request, Response};
use crate::engine::message::{QueueItemStatus, QueuedUserMessage};
use crate::tui::settings::Dialog;

impl App {
    pub(super) fn handle_key(&mut self, key: KeyEvent) -> bool {
        // Embedded pane (GOALS §1i): while a pane is open, `Ctrl+X`
        // force-closes it and `Ctrl+O` toggles focus — both reserved by
        // cockpit and not delivered to the child. When the pane is
        // focused, every other key (incl. Ctrl+C) is forwarded to the
        // child PTY rather than handled by the TUI.
        if self.pane.is_some() {
            if is_pane_force_close(&key) {
                self.close_pane(true);
                return false;
            }
            if is_pane_focus_toggle(&key) {
                self.pane_focused = !self.pane_focused;
                return false;
            }
            if self.pane_focused {
                if let Some(pane) = self.pane.as_mut() {
                    pane.forward_key(&key);
                }
                return false;
            }
        }

        // Ctrl+C: interrupt the running agent; exit only on a second press
        // within the 0.5s window (GOALS §3a). Routed through the
        // double-press state machine. Explicitly exclude Shift so that
        // Ctrl+Shift+C (copy-selection, plan.md T8.f) isn't mistaken for it
        // on terminals that report the shift state in `modifiers` even when
        // the key code is lowercase.
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && !key.modifiers.contains(KeyModifiers::SHIFT)
            && matches!(key.code, KeyCode::Char('c'))
        {
            return self.handle_ctrl_c();
        }
        // Ctrl+D preserves terminal EOF muscle memory only when the TUI is
        // truly idle. If work or modal state is active, route through the
        // same guarded exit policy as Ctrl+C so it cannot accidentally detach
        // the user from active/background work.
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && !key.modifiers.contains(KeyModifiers::SHIFT)
            && matches!(key.code, KeyCode::Char('d'))
        {
            return if self.ctrl_d_can_exit_immediately() {
                true
            } else {
                self.handle_ctrl_c()
            };
        }

        // Any meaningful keystroke dismisses the toast — the user has
        // moved on. Pure-modifier presses (Shift, Ctrl, etc. alone)
        // don't count.
        if !is_modifier_only(&key) {
            if self.toast.is_some() {
                self.toast = None;
            }
            // Record the interaction as the attention subsystem's conservative
            // "user is actively here" proxy (terminals can't report focus).
            self.last_user_interaction = Instant::now();
        }

        // Which-key overlay (`which-key-overlay.md`). When open it is fully
        // modal: route the key to it (scroll / Esc / q / leader-again close)
        // and always consume so nothing leaks underneath. The leader key also
        // closes it (toggle). TUI-only — never touches the agent or history.
        if self.keys_overlay.is_some() {
            if is_keys_leader(&key) {
                self.keys_overlay = None;
                return false;
            }
            if let Some(overlay) = self.keys_overlay.as_mut()
                && overlay.handle_key(key)
            {
                self.keys_overlay = None;
            }
            return false;
        }

        // Leader key opens the which-key overlay over the current context
        // (`which-key-overlay.md`). Routed here — after the toast dismiss but
        // ahead of the pane/dialog routing — so the leader works while a pane
        // (`/sessions`, `/plans`, settings, the startup daemon prompt, …) is
        // open and shows that context first. It is deliberately *not* honored
        // while a required agent decision (question / approval dialog) is up:
        // those prompts must not be obscured. The `dangerous-action`
        // confirm-armed states (`/prune`, `/plans` start, `/stop`) likewise
        // keep the key first.
        if is_keys_leader(&key)
            && self.question_dialog.is_none()
            && !self.pending_prune_confirm
            && self.pending_stop_confirm.is_none()
        {
            self.toggle_keys_overlay();
            return false;
        }

        // `/prune` confirm armed (T6.d): `y` / Enter commits, any other
        // non-modifier key cancels. Ahead of composer routing so the
        // keystroke doesn't leak into the textbox.
        if self.pending_prune_confirm && !is_modifier_only(&key) {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => self.commit_prune(),
                _ => self.cancel_prune(),
            }
            return false;
        }

        // Bare `/stop` confirm armed: `[y/N]` — only `y` commits; any
        // other non-modifier key (incl. Enter, since the default is No)
        // cancels. Ahead of composer routing so the keystroke doesn't
        // leak into the textbox.
        if self.pending_stop_confirm.is_some() && !is_modifier_only(&key) {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.commit_stop(),
                _ => self.cancel_stop(),
            }
            return false;
        }

        // Context menu intercepts keys while open. Arrows / j-k move
        // the focus, Enter executes, Esc dismisses, any other
        // printable key dismisses without executing (so the user can
        // resume typing into the composer without a stray menu).
        if let Some(menu) = self.context_menu.clone() {
            match key.code {
                KeyCode::Esc => {
                    self.context_menu = None;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if let Some(m) = self.context_menu.as_mut() {
                        m.move_cursor(-1);
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if let Some(m) = self.context_menu.as_mut() {
                        m.move_cursor(1);
                    }
                }
                KeyCode::Enter => {
                    self.context_menu = None;
                    if let Some(action) = menu.focused_action() {
                        self.execute_context_menu_action(action, menu.clicked_chat_row);
                    }
                }
                _ if !is_modifier_only(&key) => {
                    // Any other typed key dismisses without action.
                    self.context_menu = None;
                }
                _ => {}
            }
            return false;
        }

        // `/pin` pick-a-message mode (`pinned-messages`): modal while
        // open. ↑/↓/j/k move the left-side arrow, Enter pins the selected
        // message, Esc exits without pinning and refocuses the composer.
        // Any other non-modifier key is swallowed (the composer is
        // unfocused). Ahead of dialog/composer routing so nav chars never
        // leak into the textbox.
        if self.pin_pick.is_some() {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.pin_pick_up(),
                KeyCode::Down | KeyCode::Char('j') => self.pin_pick_down(),
                KeyCode::Enter => self.confirm_pin_pick(),
                KeyCode::Esc => self.cancel_pin_pick(),
                _ => {}
            }
            return false;
        }

        // `/fork` pick-a-message mode: modal while open. Navigation mirrors
        // `/pin`; Enter branches at the selected recorded message.
        if self.fork_pick.is_some() {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.fork_pick_up(),
                KeyCode::Down | KeyCode::Char('j') => self.fork_pick_down(),
                KeyCode::Enter => self.confirm_fork_pick(),
                KeyCode::Esc => self.cancel_fork_pick(),
                _ => {}
            }
            return false;
        }

        // `/copy-pick` keyboard message/code-block copy mode. The format
        // menu is a normal context menu and routes above this block.
        if self.copy_pick.is_some() {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.copy_pick_up(),
                KeyCode::Down | KeyCode::Char('j') => self.copy_pick_down(),
                KeyCode::Tab => self.copy_pick_cycle_target(1),
                KeyCode::BackTab => self.copy_pick_cycle_target(-1),
                KeyCode::Enter => self.open_copy_pick_format_menu(),
                KeyCode::Esc => self.cancel_copy_pick(),
                _ => {}
            }
            return false;
        }

        // `/pins` review mode (`pinned-messages`): modal while open.
        // ↑/↓/j/k scan the checklist (jumping the transcript to each pin),
        // `d` / Space (check) unpin the highlighted pin, Esc closes and
        // refocuses the composer.
        if self.pins_review.is_some() {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.pins_review_up(),
                KeyCode::Down | KeyCode::Char('j') => self.pins_review_down(),
                KeyCode::Char('d') | KeyCode::Char(' ') => self.pins_review_unpin_selected(),
                KeyCode::Esc => self.close_pins_review(),
                _ => {}
            }
            return false;
        }

        if self.handle_footer_control_key(key) {
            return false;
        }

        // Escape with an active selection: clear the selection and
        // swallow the key. Ordering: ahead of dialog routing because
        // the selection lives on App-state and isn't visible to the
        // dialog handlers; behind the Ctrl+C quit because the user
        // expects Ctrl+C to always exit regardless of selection.
        if matches!(key.code, KeyCode::Esc) && self.selection.is_some() {
            self.selection = None;
            return false;
        }

        // Modal dialog rule: whenever a modal is open we must
        // `return false` (consume the key) before any other handler
        // sees it. Otherwise navigation chars (`j`/`k`/etc.) that the
        // modal interpreted as up/down also fall through to the
        // composer's char-insert arm and leak into the textbox.
        //
        // The shape below is the same for every modal:
        //   1. let inner handle the key
        //   2. if it requested close: drain its result, close it
        //   3. unconditionally `return false`
        if let Some(prompt) = self.daemon_prompt.as_mut() {
            let should_close = prompt.handle_key(key);
            if !should_close {
                return false;
            }
            let choice = prompt.take_choice();
            match choice {
                Some(crate::tui::daemon_prompt::DaemonChoice::StartAndConnect) => {
                    // The TUI promotes a *persistent* daemon here; the
                    // client's `--no-sandbox` is a per-session default
                    // applied at attach, not a daemon-level launch flag
                    // (sandboxing part 2 precedence).
                    match crate::daemon::DaemonPaths::resolve()
                        .and_then(|_| crate::daemon::spawn_detached(false))
                    {
                        Ok(pid) => {
                            self.history.push(HistoryEntry::Plain {
                                line: format!(
                                    "daemon: spawned (pid {pid}); stop later with `cockpit daemon stop`"
                                ),
                            });
                            self.daemon_connected = true;
                            self.daemon_prompt = None;
                            self.maybe_open_add_provider_wizard();
                        }
                        Err(e) => {
                            if let Some(p) = self.daemon_prompt.as_mut() {
                                p.set_error(format!("failed to spawn daemon: {e}"));
                            }
                        }
                    }
                }
                Some(crate::tui::daemon_prompt::DaemonChoice::ContinueWithout) => {
                    // Daemonless mode: this TUI owns its own pid+nonce
                    // ephemeral daemon (isolated from the canonical daemon
                    // and from any other TUI's), spawned on the first attach
                    // and reaped when this TUI exits. Flip the lifecycle flag
                    // and mark "connected" — the latter so daemon-aware UI
                    // (e.g. the `/sessions` pane's live-RPC path) treats this
                    // window as connected. The eager display attach
                    // deliberately skips daemonless mode, so this does *not*
                    // spawn the owned ephemeral daemon just to show an id; the
                    // short id appears once the first message brings it up.
                    self.daemonless = true;
                    self.daemon_connected = true;
                    self.history.push(HistoryEntry::Plain {
                        line:
                            "daemon: running a private daemon for this window only — it shuts down when you exit"
                                .to_string(),
                    });
                    self.daemon_prompt = None;
                    self.maybe_open_add_provider_wizard();
                }
                Some(crate::tui::daemon_prompt::DaemonChoice::Exit) | None => {
                    return true;
                }
            }
            return false;
        }

        // Answering dialog (GOALS §3b) — same modal rule. It replaces the
        // composer, so it routes before the settings dialog / picker. On
        // close, send the resolution back to the daemon as
        // `ResolveInterrupt`; the agent's blocked `question` tool wakes.
        if let Some(dialog) = self.question_dialog.as_mut() {
            let should_close = dialog.handle_key(key);
            if should_close {
                let result = dialog.take_result();
                self.question_dialog = None;
                if let Some(result) = result {
                    // A local `/init` existing-file prompt resolves here
                    // (update/overwrite/cancel), not back to the daemon —
                    // matched by the synthetic interrupt id. Every other
                    // dialog is a real `question`-tool interrupt.
                    if self.init_choice_for(&result) {
                        let selected = init_selected_id(&result);
                        self.resolve_init_choice(selected.as_deref());
                    } else if self.paused_work_choice_for(&result) {
                        let selected = init_selected_id(&result);
                        self.resolve_paused_work_choice(selected.as_deref());
                    } else if self.resume_repair_choice_for(&result) {
                        let selected = init_selected_id(&result);
                        self.resolve_resume_repair_choice(selected.as_deref());
                    } else if self.redaction_toggle_choice_for(&result) {
                        // Bare `/toggle-redaction` multiselect — resolved
                        // locally, not back to the daemon as an interrupt.
                        let selected = redaction_selected_ids(&result);
                        self.resolve_redaction_toggle(selected.as_deref());
                    } else if self.tandem_select_choice_for(&result) {
                        // `/model-comparison` multiselect — resolved locally
                        // (the checked rows become the session's tandem set),
                        // not back to the daemon as an interrupt.
                        let selected = redaction_selected_ids(&result);
                        self.resolve_model_comparison_select(selected.as_deref());
                    } else {
                        self.resolve_question_dialog(result);
                    }
                }
            }
            return false;
        }

        if self.dialog.is_active() {
            if self.dialog.handle_key(key) {
                self.drain_oauth_actions();
                // Closing the settings dialog can change the active
                // provider/model — reload launch info so the status
                // line and header refresh. TUI-side settings (vim
                // mode, thinking display, markdown) are also reloaded
                // so they apply without a restart.
                self.dialog = Dialog::None;
                self.sync_mouse_capture_from_dialog();
                self.reload_launch_info();
                self.reload_tui_config();
            } else if let Some(req) = self.dialog.take_daemon_request()
                && !self.send_daemon_request(req)
            {
                self.history.push(HistoryEntry::Plain {
                    line: "⚠ daemon is not connected; LSP action was not sent".to_string(),
                });
            }
            self.drain_oauth_actions();
            return false;
        }

        if let Some(picker) = self.model_picker.as_mut() {
            let should_close = picker.handle_key(key);
            if should_close {
                // `is_done()` distinguishes an accepted pick from an Esc
                // cancel — only the former counts toward the tally.
                let accepted = picker.is_done();
                self.close_model_picker(accepted);
            }
            // See the "modal dialog rule" comment above — always
            // consume the key while the picker is open.
            return false;
        }

        if let Some(dialog) = self.multireview_dialog.as_mut() {
            let should_close = dialog.handle_key(key);
            let kickoff = dialog.take_done();
            if should_close || kickoff.is_some() {
                self.multireview_dialog = None;
            }
            if let Some(kickoff) = kickoff {
                self.start_multireview(kickoff.prompt);
            }
            return false;
        }

        // `/stats` pane (GOALS §15). Same modal rule: route the key to
        // the pane, close on its request, and always consume so nothing
        // leaks into the composer underneath.
        if let Some(pane) = self.stats_pane.as_mut() {
            if pane.handle_key(key) {
                self.stats_pane = None;
            }
            return false;
        }

        // `/usage` pane. Same modal rule as `/stats`: route the key to
        // the pane, close on request, and consume input.
        if let Some(pane) = self.usage_pane.as_mut() {
            if pane.handle_key(key) {
                self.usage_pane = None;
            }
            return false;
        }

        // `/sessions` + `/resume` browser (GOALS §17f). Same modal rule.
        // The pane returns an outcome: Close drops it; Resume drops it and
        // switches the runner onto the chosen session via the existing
        // resume path. Always consume the key.
        if let Some(pane) = self.sessions_pane.as_mut() {
            match pane.handle_key(key) {
                Some(crate::tui::sessions_pane::SessionsOutcome::Close) => {
                    self.sessions_pane = None;
                }
                Some(crate::tui::sessions_pane::SessionsOutcome::Resume(session_id)) => {
                    self.sessions_pane = None;
                    self.resume_session(session_id);
                }
                Some(crate::tui::sessions_pane::SessionsOutcome::LoadList) => {
                    self.start_sessions_list_action();
                }
                None => {}
            }
            return false;
        }

        // `/skills` overlay (read-only). Same modal rule: route the key to
        // the pane, close on its request, and always consume so nothing
        // leaks into the composer underneath.
        if let Some(pane) = self.skills_pane.as_mut() {
            if pane.handle_key(key) {
                self.skills_pane = None;
            }
            return false;
        }

        // `/permissions` overlay. Modal: route the key to the pane (it owns
        // navigation + the delete action), close on its request, and always
        // consume so nothing leaks into the composer underneath.
        if let Some(pane) = self.permissions_pane.as_mut() {
            if pane.handle_key(key) {
                self.permissions_pane = None;
            }
            return false;
        }

        if let Some(pane) = self.resources_pane.as_mut() {
            if let Some(outcome) = pane.handle_key(key) {
                self.start_resources_outcome(outcome);
            }
            return false;
        }

        if let Some(dialog) = self.quick_dialog.as_mut() {
            if let Some(outcome) = dialog.handle_key(key) {
                self.quick_dialog = None;
                match outcome {
                    crate::tui::quick_dialog::QuickOutcome::Close => {}
                    crate::tui::quick_dialog::QuickOutcome::Commit(commit) => {
                        self.apply_quick_commit(commit);
                    }
                }
            }
            return false;
        }

        // `/context` overlay (read-only snapshot). Same modal rule: route
        // the key to the pane, close on its request (Esc / q), and always
        // consume so nothing leaks into the composer underneath.
        if let Some(pane) = self.context_pane.as_mut() {
            if pane.handle_key(key) {
                self.context_pane = None;
            }
            return false;
        }

        // `/scratchpad` dialog (prompt `notes-scratchpad.md`). Same
        // modal rule: route the key to the pane, close on its request, and
        // always consume so nothing leaks into the composer underneath.
        if let Some(pane) = self.notes_pane.as_mut() {
            match pane.handle_key(key) {
                crate::tui::notes_pane::NotesOutcome::Close => {
                    // Closing returns focus to the composer/transcript — the
                    // pane is simply dropped and the composer resumes input.
                    self.notes_pane = None;
                }
                crate::tui::notes_pane::NotesOutcome::Stay => {}
            }
            return false;
        }

        // `/diff` pane (read-only diff browser). Same modal rule: route the
        // key to the pane, close on its request, and always consume so
        // nothing leaks into the composer underneath.
        if let Some(pane) = self.diff_pane.as_mut() {
            if pane.handle_key(key) {
                self.diff_pane = None;
            }
            return false;
        }

        if self.transcript_find.is_some() {
            self.handle_transcript_find_key(key);
            return false;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL)
            && !key.modifiers.contains(KeyModifiers::SHIFT)
            && matches!(key.code, KeyCode::Char('f'))
            && !self.dialog.is_active()
            && self.model_picker.is_none()
            && self.multireview_dialog.is_none()
            && self.question_dialog.is_none()
            && self.daemon_prompt.is_none()
            && self.pane.is_none()
        {
            self.open_transcript_find();
            return false;
        }

        // Ctrl+N opens the `/scratchpad` (the keyboard entry point;
        // `/scratchpad` is the always-available equivalent). Reached only when
        // no pane/modal is open — those are routed above and consume the key
        // first — so it never clashes with a pane's own bindings. Ctrl+N is
        // otherwise unbound in the composer.
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && !key.modifiers.contains(KeyModifiers::SHIFT)
            && matches!(key.code, KeyCode::Char('n'))
            && !self.dialog.is_active()
            && self.model_picker.is_none()
            && self.multireview_dialog.is_none()
            && self.question_dialog.is_none()
            && self.daemon_prompt.is_none()
            && self.pane.is_none()
        {
            self.open_scratchpad_pane();
            return false;
        }

        // Ctrl+T toggles every agent reasoning block's expand/collapse
        // state. (See the doc comment on `toggle_recent_reasoning` for
        // why this is a keybind rather than a click handler.) Only
        // intercepted when at least one entry actually has a reasoning
        // block; otherwise Ctrl+T is inert and never mutates the composer.
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('t'))
            && self.history.iter().any(|e| {
                matches!(e,
                HistoryEntry::Agent { reasoning, .. } if !reasoning.trim().is_empty())
            })
        {
            self.toggle_recent_reasoning();
            return false;
        }

        // Ctrl+E toggles every preflighted user message between its cleaned
        // form and the original typed input, and toggles compact-boundary
        // handoff briefs. Only intercepted when at least one revealable row
        // exists — otherwise Ctrl+E falls through to its composer role.
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('e'))
            && self.history.iter().any(|e| {
                matches!(
                    e,
                    HistoryEntry::User {
                        cleaned: Some(_),
                        ..
                    } | HistoryEntry::CompactBoundary { brief: Some(_), .. }
                )
            })
        {
            self.toggle_ctrl_e_reveals();
            return false;
        }

        // Ctrl+Shift+Y — copy the most-recent agent message to the
        // system clipboard as rich text (HTML + plain alt). Falls back
        // to plain text over SSH. Gated by tui.rich_text_copy.
        // (plan.md T8.g)
        if self.is_ctrl_shift_y(&key) {
            self.copy_last_agent_message_as_rich_text();
            return false;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL)
            && !key.modifiers.contains(KeyModifiers::SHIFT)
            && matches!(key.code, KeyCode::Char('y'))
        {
            self.enter_copy_pick_mode();
            return false;
        }

        // Ctrl+Shift+C — copy the active drag-selection's plaintext
        // through OSC52 (SSH-safe) + local clipboard. No-op when
        // nothing is selected. (plan.md T8.f copy path)
        if self.is_ctrl_shift_c(&key) {
            self.copy_selection_plaintext();
            return false;
        }

        // Ctrl+G — pop the composer text out into `$EDITOR`. We can't
        // suspend ratatui from inside the key handler (the terminal
        // handle lives in `event_loop`), so just request the action;
        // the loop services it before the next draw.
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('g')) {
            if std::env::var_os("EDITOR").is_none() {
                self.history.push(HistoryEntry::Plain {
                    line: "No $EDITOR environment variable".to_string(),
                });
            } else {
                self.pending_external_edit = true;
            }
            return false;
        }

        // Anything that gets this far is a composer-facing key — char
        // input, arrow nav, vim-mode keys, etc. By design the user is
        // engaging with the composer, so any active chat selection
        // becomes stale and gets in the way. Drop it before the
        // composer mutates. Modifier-only keys (Shift alone, etc.) are
        // skipped so just *holding* Shift doesn't clear the selection
        // mid-drag-extend-by-keyboard.
        if self.selection.is_some() && !is_modifier_only(&key) {
            self.selection = None;
        }

        // Shift+Tab (`BackTab`) cycles the active primary agent
        // (implementation note). Reached only in the
        // normal composer editing state: every modal/pane above consumes its
        // keys and returns first, so this fires only when the composer owns
        // the key. The slash-menu Tab-completion path deliberately leaves
        // Shift+Tab unbound (it scopes its branch to a non-Shift Tab), so
        // there is no conflict there. `BackTab` is a distinct key code, so it
        // never collides with literal text input or vim motions.
        if matches!(key.code, KeyCode::BackTab) {
            self.cycle_primary_agent();
            return false;
        }

        if self.handle_chat_scrollback_key(key) {
            return false;
        }

        // Vim-aware dispatch. Normal / Operator-pending intercept
        // char keys; Insert mode falls through to the standard editor
        // path (also used when vim is disabled).
        if self.composer.vim_enabled() {
            match self.composer.vim_mode() {
                VimMode::Normal => return self.handle_key_normal(key),
                VimMode::Operator(op) => return self.handle_key_operator(key, op),
                VimMode::Visual | VimMode::VisualLine => return self.handle_key_visual(key),
                VimMode::Insert => {}
            }
        }
        self.handle_key_insert(key)
    }

    fn handle_footer_control_key(&mut self, key: KeyEvent) -> bool {
        if let Some(mut picker) = self.footer_agent_picker.take() {
            match key.code {
                KeyCode::Esc => {
                    self.footer_selection = None;
                    return true;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    picker.prev();
                    self.footer_agent_picker = Some(picker);
                    return true;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    picker.next();
                    self.footer_agent_picker = Some(picker);
                    return true;
                }
                KeyCode::Enter => {
                    self.commit_footer_agent_picker(&picker);
                    return true;
                }
                _ if !is_modifier_only(&key) => {
                    self.footer_agent_picker = None;
                    self.footer_selection = None;
                    return false;
                }
                _ => {
                    self.footer_agent_picker = Some(picker);
                    return true;
                }
            }
        }

        if let Some(mut picker) = self.footer_mode_picker {
            match key.code {
                KeyCode::Esc => {
                    self.footer_mode_picker = None;
                    self.footer_selection = None;
                    return true;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    picker.prev();
                    self.footer_mode_picker = Some(picker);
                    return true;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    picker.next();
                    self.footer_mode_picker = Some(picker);
                    return true;
                }
                KeyCode::Enter => {
                    self.footer_mode_picker = None;
                    self.footer_selection = None;
                    self.set_footer_llm_mode(picker.selected_mode());
                    return true;
                }
                _ if !is_modifier_only(&key) => {
                    self.footer_mode_picker = None;
                    self.footer_selection = None;
                    return false;
                }
                _ => return true,
            }
        }

        let Some(selected) = self.footer_selection else {
            return false;
        };
        match key.code {
            KeyCode::Esc => {
                self.footer_selection = None;
                true
            }
            KeyCode::Left | KeyCode::Char('h') => {
                match selected {
                    crate::tui::chrome::FooterControl::Agent => self.footer_cycle_agent(),
                    crate::tui::chrome::FooterControl::Model => self.cycle_footer_model(false),
                    crate::tui::chrome::FooterControl::Mode => {
                        self.set_footer_llm_mode(App::previous_llm_mode(self.llm_mode));
                    }
                }
                true
            }
            KeyCode::Right | KeyCode::Char('l') => {
                match selected {
                    crate::tui::chrome::FooterControl::Agent => self.footer_cycle_agent(),
                    crate::tui::chrome::FooterControl::Model => self.cycle_footer_model(true),
                    crate::tui::chrome::FooterControl::Mode => {
                        self.set_footer_llm_mode(self.llm_mode.cycled());
                    }
                }
                true
            }
            KeyCode::Enter => {
                match selected {
                    crate::tui::chrome::FooterControl::Agent => self.open_footer_agent_picker(),
                    crate::tui::chrome::FooterControl::Model => {
                        self.footer_selection = None;
                        self.open_model_picker();
                    }
                    crate::tui::chrome::FooterControl::Mode => {
                        self.open_footer_mode_picker();
                    }
                }
                true
            }
            _ if !is_modifier_only(&key) => {
                self.footer_selection = None;
                false
            }
            _ => true,
        }
    }

    fn handle_chat_scrollback_key(&mut self, key: KeyEvent) -> bool {
        let page = self.chat_visible_lines.saturating_sub(1).max(1);
        match key.code {
            KeyCode::PageUp => {
                self.scroll_chat_up(page);
                true
            }
            KeyCode::PageDown => {
                self.scroll_chat_down(page);
                true
            }
            KeyCode::Up if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.scroll_chat_up(1);
                true
            }
            KeyCode::Down if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.scroll_chat_down(1);
                true
            }
            KeyCode::End if self.composer.is_empty() => {
                self.scroll_chat_down(self.chat_scroll_offset);
                true
            }
            _ => false,
        }
    }

    fn ctrl_d_can_exit_immediately(&self) -> bool {
        self.composer.is_empty()
            && !self.busy
            && self.queue.is_empty()
            && self.pending.is_none()
            && self.active_schedules.is_empty()
            && matches!(self.dialog, Dialog::None)
            && self.model_picker.is_none()
            && self.multireview_dialog.is_none()
            && self.stats_pane.is_none()
            && self.usage_pane.is_none()
            && self.sessions_pane.is_none()
            && self.skills_pane.is_none()
            && self.permissions_pane.is_none()
            && self.resources_pane.is_none()
            && self.quick_dialog.is_none()
            && self.context_pane.is_none()
            && self.notes_pane.is_none()
            && self.diff_pane.is_none()
            && self.daemon_prompt.is_none()
            && self.question_dialog.is_none()
            && self.pending_init.is_none()
            && self.pending_paused_work.is_none()
            && self.pending_resume_repair.is_none()
            && !self.pending_prune_confirm
            && self.pending_stop_confirm.is_none()
            && self.pending_redaction_toggle.is_none()
            && self.pending_tandem_select.is_none()
            && self.pending_compact.is_none()
            && !self.pending_external_edit
            && self.context_menu.is_none()
            && self.pane.is_none()
            && self.pin_pick.is_none()
            && self.pins_review.is_none()
            && self.keys_overlay.is_none()
    }

    pub(super) fn handle_key_insert(&mut self, key: KeyEvent) -> bool {
        // `@`-popup intercepts navigation + accept keys when active.
        if self.at_popup_active() {
            match key.code {
                KeyCode::Esc => {
                    self.at_dismissed = true;
                    self.at_selected = 0;
                    return false;
                }
                KeyCode::Up => {
                    let n = self.at_suggestions().len();
                    if n > 0 {
                        // Wrap at the top (first → last) + scrolloff so the
                        // neighbor stays visible (see `windowed_scroll`).
                        self.at_selected = crate::tui::nav::wrap_prev(self.at_selected, n);
                        self.at_scroll = super::windowed_scroll(
                            self.at_selected,
                            self.at_scroll,
                            n,
                            super::AUTOCOMPLETE_ROWS as usize,
                        );
                    }
                    return false;
                }
                KeyCode::Down => {
                    let n = self.at_suggestions().len();
                    if n > 0 {
                        // Wrap at the bottom (last → first).
                        self.at_selected = crate::tui::nav::wrap_next(self.at_selected, n);
                        self.at_scroll = super::windowed_scroll(
                            self.at_selected,
                            self.at_scroll,
                            n,
                            super::AUTOCOMPLETE_ROWS as usize,
                        );
                    }
                    return false;
                }
                KeyCode::Tab => {
                    // Tab finalizes a file (space + close) but *descends*
                    // into a directory (no space, popup stays open).
                    if self.accept_at_suggestion(false) {
                        return false;
                    }
                    // No suggestion to take — Tab is otherwise inert.
                    return false;
                }
                // Enter finalizes whatever is highlighted, file or dir; with
                // no matches it dismisses the popup and consumes the key.
                KeyCode::Enter
                    if !key.modifiers.contains(KeyModifiers::SHIFT)
                        && !key.modifiers.contains(KeyModifiers::ALT) =>
                {
                    if self.accept_at_suggestion(true) {
                        return false;
                    }
                    self.at_dismissed = true;
                    self.at_selected = 0;
                    self.at_scroll = 0;
                    return false;
                }
                _ => {}
            }
        }
        // Slash-menu intercepts Up/Down while it's visible so they move
        // the highlight instead of triggering composer history recall
        // (the suppression is scoped to "menu showing" — Up/Down resume
        // normal recall the moment the menu closes). `j`/`k` are NOT
        // navigation here: the user is typing to filter, so they stay
        // literal text (matching the `@` menu). Mutually exclusive with
        // the `@`-popup (one needs a leading `/`, the other an `@`-token).
        if self.slash_query().is_some() {
            match key.code {
                KeyCode::Up => {
                    let n = self.slash_suggestions().len();
                    if n > 0 {
                        self.slash_selected = crate::tui::nav::wrap_prev(self.slash_selected, n);
                        self.slash_scroll = super::windowed_scroll(
                            self.slash_selected,
                            self.slash_scroll,
                            n,
                            super::AUTOCOMPLETE_ROWS as usize,
                        );
                    }
                    return false;
                }
                KeyCode::Down => {
                    let n = self.slash_suggestions().len();
                    if n > 0 {
                        self.slash_selected = crate::tui::nav::wrap_next(self.slash_selected, n);
                        self.slash_scroll = super::windowed_scroll(
                            self.slash_selected,
                            self.slash_scroll,
                            n,
                            super::AUTOCOMPLETE_ROWS as usize,
                        );
                    }
                    return false;
                }
                // Plain Tab completes the composer to the highlighted
                // command (cycling forward on repeat) without submitting
                // (`slash-command-tab-completion.md`). Scoped to a plain
                // Tab inside the open slash menu: Shift+Tab is reserved for
                // agent cycling, and the `@`-popup / prediction-ghost Tab
                // paths are handled elsewhere and never reach here (the
                // `@`-popup block above returns first, and this branch only
                // fires while a slash query is active). A zero-match menu is
                // a no-op; either way we consume the key.
                KeyCode::Tab if !key.modifiers.contains(KeyModifiers::SHIFT) => {
                    self.complete_slash_selection();
                    return false;
                }
                _ => {}
            }
        }
        match key.code {
            // Ghost-text accept (implementation note): Tab in
            // insert mode, while the box is empty with a pending prediction,
            // accepts the ghost. A `long` multi-line prediction's first Tab
            // expands the box to the full ghost; the next Tab (and every
            // single-line/`short` case) fills the composer with real
            // editable text — it does NOT send. With no ghost, Tab is inert
            // (this path is reached only when the `@`-popup is closed).
            KeyCode::Tab if self.composer.is_empty() && self.prediction_state.ghost().is_some() => {
                self.accept_prediction_ghost();
                false
            }
            KeyCode::Esc => {
                // Esc cancels an in-progress slash command. Otherwise:
                // when vim is enabled, it drops the composer into
                // Normal mode. When vim is disabled it's a no-op
                // (deliberate — too easy to hit accidentally for an
                // exit path; `/exit`, Ctrl+C, Ctrl+D cover that).
                if self.slash_query().is_some() {
                    self.composer.clear();
                    self.paste_registry.clear();
                    self.reset_slash_window();
                } else if self.composer.vim_enabled() {
                    self.composer.set_vim_mode(VimMode::Normal);
                    self.composer.set_pending_g(false);
                }
                false
            }
            KeyCode::Enter => {
                if key.modifiers.contains(KeyModifiers::SHIFT)
                    || key.modifiers.contains(KeyModifiers::ALT)
                {
                    self.composer_insert_char('\n');
                    self.refresh_at_dismiss();
                    self.reset_slash_window();
                    false
                } else {
                    self.complete_or_submit()
                }
            }
            // Newline fallback for terminals that can't disambiguate
            // Shift+Enter (most legacy terminfo entries, every plain
            // xterm-256color, and the common path through tmux+ssh
            // without the kitty keyboard protocol). Ctrl+J is the
            // canonical LF on every Unix terminal and survives every
            // multiplexer hop.
            KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.composer_insert_char('\n');
                self.reset_slash_window();
                false
            }
            KeyCode::Backspace => {
                // Whole-block delete (paste blocks): cursor immediately
                // right of `]` removes the entire block. Checked before
                // the `@`-tag path since blocks are explicit + atomic.
                if let Some((s, e)) = self.paste_block_left() {
                    self.delete_paste_block(s, e);
                    self.refresh_at_dismiss();
                    self.reset_at_window();
                    return false;
                }
                // Whole-tag delete: when not actively composing a tag
                // (popup closed) and the cursor sits at a completed
                // tag's right edge, one Backspace removes the whole tag.
                if !self.at_popup_active()
                    && let Some((s, e)) = self.completed_tag_left()
                {
                    self.composer.delete_range(s, e);
                    self.refresh_at_dismiss();
                    self.reset_at_window();
                    return false;
                }
                self.composer_delete_left();
                // Two-keystroke trailing space: if we just removed a
                // space that sat right after a completed tag, keep the
                // popup suppressed so the *next* Backspace deletes the
                // whole tag rather than re-opening the popup on it.
                if self.completed_tag_left().is_some() {
                    self.at_dismissed = true;
                } else {
                    self.refresh_at_dismiss();
                }
                self.reset_at_window();
                self.reset_slash_window();
                false
            }
            KeyCode::Delete => {
                // Whole-block forward delete: cursor immediately left of
                // `[` removes the entire block.
                if let Some((s, e)) = self.paste_block_right() {
                    self.delete_paste_block(s, e);
                    self.refresh_at_dismiss();
                    self.reset_at_window();
                    return false;
                }
                if !self.at_popup_active()
                    && let Some((s, e)) = self.completed_tag_right()
                {
                    self.composer.delete_range(s, e);
                    self.refresh_at_dismiss();
                    self.reset_at_window();
                    return false;
                }
                self.composer_delete_right();
                self.refresh_at_dismiss();
                self.reset_at_window();
                self.reset_slash_window();
                false
            }
            KeyCode::Left => {
                self.composer_move_left();
                false
            }
            KeyCode::Right => {
                self.composer_move_right();
                false
            }
            KeyCode::Up => {
                self.history_up();
                false
            }
            KeyCode::Down => {
                self.history_down();
                false
            }
            KeyCode::Home => {
                self.composer.move_line_start();
                false
            }
            KeyCode::End => {
                self.composer.move_line_end();
                false
            }
            KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.composer_insert_char(normalize_shift_char(&key, ch));
                // Note: we deliberately do NOT reset
                // `prompt_history_cursor` here. Edits made while in
                // recall mode stay in the buffer, but pressing Down
                // back to cursor 0 still restores the original
                // staged draft — matching the user-visible spec for
                // history navigation.
                self.refresh_at_dismiss();
                self.reset_at_window();
                // Typing narrows the slash matches; snap the cursor back
                // to the top match so it never points past the new set.
                self.reset_slash_window();
                false
            }
            _ => false,
        }
    }

    /// Shell-style "go back through prompt history" — the Up key.
    ///
    /// Rule (matches user spec): history only advances when the
    /// composer cursor is on the *top* line of the current text.
    /// Otherwise Up just moves the cursor up one line within the
    /// buffer. The first transition into history mode snapshots the
    /// live buffer into `staged_draft` so a later Down can restore
    /// it.
    pub(super) fn history_up(&mut self) {
        // Buffer empty + queue non-empty -> ask the daemon to unqueue every
        // editable foreground item before making the group editable.
        if self.prompt_history_cursor == 0 && self.composer.is_empty() && !self.queue.is_empty() {
            self.edit_queued_messages();
            return;
        }
        if !cursor_on_first_line(self.composer.text(), self.composer.cursor()) {
            self.composer.move_up();
            return;
        }
        if self.prompt_history.is_empty() {
            return;
        }
        if self.prompt_history_cursor == 0 {
            // Entering history mode — save the live draft so we can
            // restore it on the way back. `None` if the buffer was
            // empty (nothing meaningful to restore). Paste blocks are
            // flattened to their placeholder text in the recalled draft;
            // the registry is dropped (it indexed the live buffer).
            let draft = self.composer.text().to_string();
            self.staged_draft = if draft.is_empty() { None } else { Some(draft) };
            self.prompt_history_cursor = 1;
            let idx = self.prompt_history.len() - 1;
            self.composer.set(self.prompt_history[idx].clone());
            self.paste_registry.clear();
        } else if self.prompt_history_cursor < self.prompt_history.len() {
            self.prompt_history_cursor += 1;
            let idx = self.prompt_history.len() - self.prompt_history_cursor;
            self.composer.set(self.prompt_history[idx].clone());
            self.paste_registry.clear();
        }
    }

    /// Counterpart to [`Self::history_up`]. Down only steps history
    /// when the composer cursor is on the *bottom* line of the
    /// current text. Otherwise it just moves the cursor down a line.
    /// Stepping past the newest entry (`cursor 1 → 0`) restores the
    /// `staged_draft` if there was one, else clears the composer.
    pub(super) fn history_down(&mut self) {
        if !cursor_on_last_line(self.composer.text(), self.composer.cursor()) {
            self.composer.move_down();
            return;
        }
        if self.prompt_history_cursor == 0 {
            // Not in history mode and already on the bottom line —
            // nothing to do (don't move_down because there's no row
            // below to move to).
            return;
        }
        self.prompt_history_cursor -= 1;
        if self.prompt_history_cursor == 0 {
            // Out of history — restore the saved draft, if any.
            match self.staged_draft.take() {
                Some(draft) => self.composer.set(draft),
                None => self.composer.clear(),
            }
        } else {
            let idx = self.prompt_history.len() - self.prompt_history_cursor;
            self.composer.set(self.prompt_history[idx].clone());
        }
        // History navigation always lands on plain recalled text — no
        // paste blocks survive.
        self.paste_registry.clear();
    }

    /// If the composer no longer has an active `@partial` token, clear
    /// the dismissal latch so the next `@` reopens the popup. Otherwise
    /// (token still present) keep the existing state untouched.
    pub(super) fn refresh_at_dismiss(&mut self) {
        if self.composer.at_query().is_none() {
            self.at_dismissed = false;
            self.at_selected = 0;
            self.at_scroll = 0;
        }
    }

    /// Span of a completed `@`-tag whose right edge is at the cursor (for
    /// Backspace whole-tag delete), or `None`.
    pub(super) fn completed_tag_left(&self) -> Option<(usize, usize)> {
        completed_tag_span(
            self.composer.text(),
            self.composer.cursor(),
            &self.accepted_tags,
        )
    }

    /// Span of a completed `@`-tag whose left edge is at the cursor (for
    /// forward-`Delete` whole-tag delete), or `None`.
    pub(super) fn completed_tag_right(&self) -> Option<(usize, usize)> {
        completed_tag_span_forward(
            self.composer.text(),
            self.composer.cursor(),
            &self.accepted_tags,
        )
    }

    /// Reset the `@`-popup highlight + scroll window to the top. Called
    /// after any composer edit that changes the active `@`-query (typing
    /// narrows the list, so the selection should jump back to the first
    /// match). Harmless when no popup is active.
    pub(super) fn reset_at_window(&mut self) {
        self.at_selected = 0;
        self.at_scroll = 0;
    }

    /// Reset the slash-popup highlight + scroll window to the top (the
    /// frequency-ranked match). Called after any composer edit that
    /// changes the active slash query so the cursor doesn't point past a
    /// narrowed match set; also restores the "Enter runs the top match"
    /// default. Harmless when no slash query is active.
    pub(super) fn reset_slash_window(&mut self) {
        self.slash_selected = 0;
        self.slash_scroll = 0;
        // A non-Tab composer edit changes the live query, so any
        // in-progress Tab-completion cycle is abandoned: drop the anchored
        // stem and let the menu re-derive from the freshly typed text
        // (`slash-command-tab-completion.md`).
        self.slash_cycle_stem = None;
        self.refresh_slash_menu_cache();
    }

    /// Tab inside an open slash menu: complete the composer to the
    /// highlighted command, or — when the composer already holds that
    /// completion — advance to the next match and complete to it, cycling
    /// forward the same way ↑/↓ moves the highlight
    /// (`slash-command-tab-completion.md`). Never runs or submits; leaves
    /// the cursor after the inserted command (plus a trailing space for
    /// arg-taking commands). A no-op when the menu has zero matches.
    /// Returns true when the slash menu was open (so the caller consumes
    /// the key), false when there was no slash menu to act on.
    pub(super) fn complete_slash_selection(&mut self) -> bool {
        if self.slash_query().is_none() {
            return false;
        }
        // Snapshot the per-match completion texts up front (owned) so the
        // `self`-borrow from `slash_suggestions` — which now references
        // `self.skill_commands` for dynamic skill entries — doesn't outlive
        // the cursor/scroll mutations below.
        let completions: Vec<String> = self
            .slash_suggestions()
            .iter()
            .map(super::SlashEntry::completion_text)
            .collect();
        if completions.is_empty() {
            // Menu open but nothing matches — Tab is inert.
            return true;
        }
        // Anchor cycling on the stem the user originally typed, captured on
        // the first Tab before the completion rewrites the composer to a
        // full `/name` (which would otherwise collapse the candidate set).
        if self.slash_cycle_stem.is_none() {
            self.slash_cycle_stem = self.slash_query().map(str::to_string);
        }
        let n = completions.len();
        let idx = self.slash_selected.min(n - 1);
        // A repeat Tab — the composer already equals the highlighted
        // command's completion — advances to the next match before
        // completing, so successive Tabs walk the list.
        if self.composer.text() == completions[idx] {
            self.slash_selected = crate::tui::nav::wrap_next(idx, n);
            self.slash_scroll = super::windowed_scroll(
                self.slash_selected,
                self.slash_scroll,
                n,
                super::AUTOCOMPLETE_ROWS as usize,
            );
        }
        let chosen = self.slash_selected.min(n - 1);
        // `set` resets the cursor to the end — exactly after the inserted
        // command (and its trailing space, if any).
        self.composer.set(completions[chosen].clone());
        true
    }

    /// Accept the currently-highlighted `@`-suggestion: replace the
    /// active `@partial` with the chosen path (trailing `/` for dirs).
    /// Returns true if a replacement was applied.
    ///
    /// `enter` distinguishes the two accept keys:
    /// - `Enter` (`enter = true`) **finalizes** any selection — file or
    ///   directory: appends a trailing space and closes the popup.
    /// - `Tab` (`enter = false`) finalizes a **file** the same way, but
    ///   on a **directory** *descends* — no trailing space, popup stays
    ///   open, and `at_query` now returns `<dir>/` so suggestions
    ///   re-query inside it.
    pub(super) fn accept_at_suggestion(&mut self, enter: bool) -> bool {
        let suggestions = self.at_suggestions();
        if suggestions.is_empty() {
            return false;
        }
        let idx = self.at_selected.min(suggestions.len() - 1);
        let sug = suggestions[idx].clone();
        self.composer.replace_at_token(&sug.replacement);
        self.at_selected = 0;
        self.at_scroll = 0;

        let finalize = enter || !sug.is_dir;
        if finalize {
            // Record spaced/special paths so the submit-time quoting
            // pass (file_tag) can wrap them — keeps the display clean
            // while the wire payload stays unambiguous.
            self.note_accepted_tag(&sug.replacement);
            // Tally the committed tag (per-project) for frequency-ranked
            // autocomplete. Tab-descending into a directory isn't a
            // commit, so it's deliberately not counted here.
            let project_id = self.project_id.clone();
            self.record_usage(
                crate::daemon::proto::UsageKind::Tag,
                sug.replacement.clone(),
                project_id,
            );
            // Trailing space terminates the tag and closes the popup.
            self.composer.insert_char(' ');
            self.at_dismissed = true;
        }
        // Dir-descend (Tab on a directory): `replacement` ends with `/`,
        // so the active `@`-query is now `<dir>/` and the popup re-walks
        // inside it. Nothing else to do.
        true
    }

    /// Render each `@`-tag expansion as a harness-automatic tool-call
    /// line in the chat (GOALS §1e). One line per tag, in the same
    /// `→ tool(path)` idiom the agent's own tools use, with a ✓/✗ + the
    /// detail (lines read / entries listed / why it was skipped).
    pub(super) fn push_tag_call_entries(
        &mut self,
        expansions: &[crate::tui::file_tag::TagExpansion],
    ) {
        for e in expansions {
            let mark = if e.ok { '✓' } else { '✗' };
            self.history.push(HistoryEntry::Plain {
                line: format!("  → {}({}) {mark} {}", e.tool, e.path, e.detail),
            });
        }
    }

    /// Remember an accepted tag path that contains a space or other
    /// shell-special character, so the submit-time pass can quote it.
    /// Plain paths need no tracking and are skipped.
    pub(super) fn note_accepted_tag(&mut self, path: &str) {
        if crate::tui::file_tag::needs_quoting(path)
            && !self.accepted_tags.contains(&path.to_string())
        {
            self.accepted_tags.push(path.to_string());
        }
    }

    pub(super) fn handle_key_normal(&mut self, key: KeyEvent) -> bool {
        // While the slash menu is visible, the arrow keys move its
        // highlight rather than recalling history — same rule as Insert
        // mode, so the menu behaves identically regardless of vim mode.
        // (`j`/`k` keep their Normal-mode vim meaning; only the arrows
        // are menu-nav, mirroring the `@`-popup's arrow-only contract.)
        if self.slash_query().is_some() && matches!(key.code, KeyCode::Up | KeyCode::Down) {
            let n = self.slash_suggestions().len();
            if n > 0 {
                self.slash_selected = if matches!(key.code, KeyCode::Up) {
                    crate::tui::nav::wrap_prev(self.slash_selected, n)
                } else {
                    crate::tui::nav::wrap_next(self.slash_selected, n)
                };
                self.slash_scroll = super::windowed_scroll(
                    self.slash_selected,
                    self.slash_scroll,
                    n,
                    super::AUTOCOMPLETE_ROWS as usize,
                );
            }
            self.composer.set_pending_g(false);
            return false;
        }
        // Plain Tab completes the highlighted slash command here too, so
        // the menu behaves identically in Normal mode (Tab isn't a vim
        // motion). Shift+Tab is reserved for agent cycling, so only plain
        // Tab is bound. (`slash-command-tab-completion.md`)
        if self.slash_query().is_some()
            && matches!(key.code, KeyCode::Tab)
            && !key.modifiers.contains(KeyModifiers::SHIFT)
        {
            self.complete_slash_selection();
            self.composer.set_pending_g(false);
            return false;
        }
        // Arrow keys + Backspace/Delete still work in Normal mode —
        // they're convenient even for vim users. Char keys go through
        // the vim dispatcher below.
        match key.code {
            KeyCode::Esc => {
                // Already in Normal; clear any pending `g`.
                self.composer.set_pending_g(false);
                false
            }
            KeyCode::Enter => {
                self.composer.set_pending_g(false);
                // Shift+Enter / Alt+Enter inserts a newline regardless
                // of mode — composer is a chat input, not a vim
                // editor, and users expect newline-on-shift to work
                // even if they forgot to switch modes. Plain Enter
                // still submits (matches most TUIs).
                if key.modifiers.contains(KeyModifiers::SHIFT)
                    || key.modifiers.contains(KeyModifiers::ALT)
                {
                    self.composer.insert_char('\n');
                    return false;
                }
                self.complete_or_submit()
            }
            KeyCode::Left => {
                self.composer.move_left();
                self.composer.set_pending_g(false);
                false
            }
            KeyCode::Right => {
                self.composer.move_right();
                self.composer.set_pending_g(false);
                false
            }
            KeyCode::Up => {
                self.history_up();
                self.composer.set_pending_g(false);
                false
            }
            KeyCode::Down => {
                self.history_down();
                self.composer.set_pending_g(false);
                false
            }
            KeyCode::Char(ch) => {
                let was_pending_g = self.composer.pending_g();
                let pending_find = self.composer.pending_find();
                // Default: any char key clears the pending `g`/`f`/`F`/`t`;
                // the `g`/find arms below re-arm them if applicable.
                self.composer.set_pending_g(false);
                self.composer.set_pending_find(None);
                if let Some(mut spec) = pending_find {
                    spec.target = ch;
                    self.vim_find_motion(spec);
                    return false;
                }
                // `ge` / `gE` — backward end-of-word (the `g` was pending).
                if was_pending_g && (ch == 'e' || ch == 'E') {
                    self.vim_motion(|c| c.move_word_end_backward(ch == 'E'), false);
                    return false;
                }
                match ch {
                    'h' => self.composer_move_left(),
                    'l' => self.composer_move_right(),
                    'k' => self.history_up(),
                    'j' => self.history_down(),
                    'w' => self.vim_motion(|c| c.move_word_forward(false), true),
                    'W' => self.vim_motion(|c| c.move_word_forward(true), true),
                    'b' => self.vim_motion(|c| c.move_word_backward(false), false),
                    'B' => self.vim_motion(|c| c.move_word_backward(true), false),
                    'e' => self.vim_motion(|c| c.move_word_end(false), true),
                    'E' => self.vim_motion(|c| c.move_word_end(true), true),
                    '0' => self.composer.move_line_start(),
                    '$' => self.composer.move_line_end(),
                    'G' => self.composer.move_buffer_end(),
                    '%' => self.vim_motion(|c| c.match_bracket(), true),
                    ';' => {
                        self.composer.repeat_find(false);
                        self.snap_off_block(true);
                    }
                    ',' => {
                        self.composer.repeat_find(true);
                        self.snap_off_block(false);
                    }
                    'g' => {
                        if was_pending_g {
                            // `gg` start, or `ge` end-of-prev-word (handled
                            // by the next key); plain `gg` here.
                            self.composer.move_buffer_start();
                        } else {
                            self.composer.set_pending_g(true);
                        }
                    }
                    'f' => self.composer.set_pending_find(Some(find_spec(false, true))),
                    'F' => self
                        .composer
                        .set_pending_find(Some(find_spec(false, false))),
                    't' => self.composer.set_pending_find(Some(find_spec(true, true))),
                    'T' => self.composer.set_pending_find(Some(find_spec(true, false))),
                    'v' => self.composer.begin_visual(VimMode::Visual),
                    'V' => self.composer.begin_visual(VimMode::VisualLine),
                    'i' => self.composer.set_vim_mode(VimMode::Insert),
                    'I' => {
                        self.composer.move_line_start();
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                    'a' => {
                        self.composer_move_right();
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                    'A' => {
                        self.composer.move_line_end();
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                    'x' => {
                        // Block-aware single forward delete: if the cursor
                        // sits at a block's opening `[`, remove the whole
                        // block; else ordinary forward-delete (yanking the
                        // removed char into the register).
                        if let Some((s, e)) = self.paste_block_right() {
                            self.delete_paste_block(s, e);
                        } else {
                            self.vim_cut_char_forward();
                        }
                    }
                    'D' => {
                        self.block_aware_delete(|c| c.move_line_end(), |c| c.delete_to_line_end())
                    }
                    'C' => {
                        self.block_aware_delete(|c| c.move_line_end(), |c| c.delete_to_line_end());
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                    'o' => {
                        self.composer.open_below();
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                    'O' => {
                        self.composer.open_above();
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                    'p' => self.vim_paste(true),
                    'P' => self.vim_paste(false),
                    'd' => self
                        .composer
                        .set_vim_mode(VimMode::Operator(Operator::Delete)),
                    'c' => self
                        .composer
                        .set_vim_mode(VimMode::Operator(Operator::Change)),
                    'y' => self
                        .composer
                        .set_vim_mode(VimMode::Operator(Operator::Yank)),
                    _ => {}
                }
                false
            }
            _ => false,
        }
    }

    /// Operator-pending: we just saw `d` or `c`; the next key is the
    /// motion. `dd`/`cc` (doubled operator) deletes/changes the
    /// current line; `dw`/`cw` etc. apply the operator to the range
    /// covered by the motion. Any unrecognized key cancels back to
    /// Normal.
    pub(super) fn clear_vim_transient_state(&mut self) {
        self.composer.set_pending_g(false);
        self.composer.set_pending_find(None);
        self.pending_text_object = None;
    }

    pub(super) fn handle_key_operator(&mut self, key: KeyEvent, op: Operator) -> bool {
        // Esc always cancels operator-pending.
        if matches!(key.code, KeyCode::Esc) {
            self.composer.set_vim_mode(VimMode::Normal);
            self.clear_vim_transient_state();
            return false;
        }
        // A pending find (`df<c>`, `ct<c>`, `yf<c>`): the next char is the
        // target. Apply the operator over the motion's range.
        if let Some(mut spec) = self.composer.pending_find() {
            self.composer.set_pending_find(None);
            if let KeyCode::Char(ch) = key.code {
                spec.target = ch;
                let from = self.composer.cursor();
                let landed = self.composer.find_target(spec);
                self.composer.set_last_find(spec);
                if let Some(to) = landed {
                    // `f`/`t` are inclusive of the landing char going
                    // forward; the range helper handles inclusivity by
                    // operating on the byte span. For a forward find we
                    // include the target cell.
                    let hi = if spec.forward {
                        self.composer
                            .text()
                            .get(to..)
                            .and_then(|s| s.chars().next())
                            .map(|c| to + c.len_utf8())
                            .unwrap_or(to)
                    } else {
                        to
                    };
                    let (lo, hi) = if spec.forward { (from, hi) } else { (to, from) };
                    self.apply_operator_range(op, lo, hi);
                    return false;
                }
            }
            // No target / unfound — cancel cleanly.
            self.composer.set_vim_mode(VimMode::Normal);
            return false;
        }
        // A pending `a`/`i` text-object selector: the next char is the
        // object (`diw`, `ci"`, `ya(`).
        if let Some(around) = self.pending_text_object.take() {
            if let KeyCode::Char(obj) = key.code
                && let Some((lo, hi)) = self.composer.text_object_range(obj, around)
                && lo < hi
            {
                self.apply_operator_range(op, lo, hi);
                return false;
            }
            // No match / zero-width — clean no-op back to Normal.
            self.composer.set_vim_mode(VimMode::Normal);
            return false;
        }
        // Pending `g` for `dgg`/`dge` chords.
        if let KeyCode::Char(c @ ('g' | 'e' | 'E')) = key.code {
            if self.composer.pending_g() {
                self.composer.set_pending_g(false);
                if c == 'g' {
                    // `dgg` — operate from buffer start to cursor.
                    let from = self.composer.cursor();
                    let to = self.composer.probe_motion(|c| c.move_buffer_start());
                    self.apply_operator_range(op, to, from);
                } else {
                    // `dge` — backward end-of-word (inclusive of the
                    // landing char).
                    let big = c == 'E';
                    let from = self.composer.cursor();
                    let to = self
                        .composer
                        .probe_motion(|comp| comp.move_word_end_backward(big));
                    self.apply_operator_range(op, to, from);
                }
                return false;
            }
            if c == 'g' {
                self.composer.set_pending_g(true);
                return false;
            }
        }
        self.composer.set_pending_g(false);
        // Find prefixes inside an operator.
        match key.code {
            KeyCode::Char('f') => {
                self.composer.set_pending_find(Some(find_spec(false, true)));
                return false;
            }
            KeyCode::Char('F') => {
                self.composer
                    .set_pending_find(Some(find_spec(false, false)));
                return false;
            }
            KeyCode::Char('t') => {
                self.composer.set_pending_find(Some(find_spec(true, true)));
                return false;
            }
            KeyCode::Char('T') => {
                self.composer.set_pending_find(Some(find_spec(true, false)));
                return false;
            }
            KeyCode::Char('i') => {
                self.pending_text_object = Some(false);
                return false;
            }
            KeyCode::Char('a') => {
                self.pending_text_object = Some(true);
                return false;
            }
            _ => {}
        }
        let applied = match key.code {
            KeyCode::Char('w') => self.apply_operator_motion(op, |c| c.move_word_forward(false)),
            KeyCode::Char('W') => self.apply_operator_motion(op, |c| c.move_word_forward(true)),
            KeyCode::Char('b') => self.apply_operator_motion(op, |c| c.move_word_backward(false)),
            KeyCode::Char('B') => self.apply_operator_motion(op, |c| c.move_word_backward(true)),
            KeyCode::Char('e') => {
                self.apply_operator_motion_inclusive(op, |c| c.move_word_end(false))
            }
            KeyCode::Char('E') => {
                self.apply_operator_motion_inclusive(op, |c| c.move_word_end(true))
            }
            KeyCode::Char('%') => self.apply_operator_motion_inclusive(op, |c| c.match_bracket()),
            KeyCode::Char(';') => self.apply_operator_motion(op, |c| {
                c.repeat_find(false);
            }),
            KeyCode::Char(',') => self.apply_operator_motion(op, |c| {
                c.repeat_find(true);
            }),
            KeyCode::Char('$') => self.apply_operator_motion(op, |c| c.move_line_end()),
            KeyCode::Char('0') => self.apply_operator_motion(op, |c| c.move_line_start()),
            KeyCode::Char('G') => {
                let len = self.composer.len();
                self.apply_operator_motion(op, move |c| c.set_cursor(len))
            }
            KeyCode::Char('d') if matches!(op, Operator::Delete) => {
                self.delete_current_line_block_aware();
                true
            }
            KeyCode::Char('c') if matches!(op, Operator::Change) => {
                // `cc` changes the current line: clear the line's content,
                // leave the line itself, and enter Insert.
                self.composer.move_line_start();
                self.block_aware_delete(|c| c.move_line_end(), |c| c.delete_to_line_end());
                true
            }
            KeyCode::Char('y') if matches!(op, Operator::Yank) => {
                // `yy` — yank the current line linewise.
                self.composer.yank_current_line();
                self.mirror_register_to_clipboard();
                true
            }
            _ => false,
        };
        if applied {
            self.finish_operator(op);
        } else {
            self.composer.set_vim_mode(VimMode::Normal);
        }
        false
    }

    /// Leave operator-pending after a successful op: Change enters Insert,
    /// Delete/Yank return to Normal.
    fn finish_operator(&mut self, op: Operator) {
        self.composer
            .set_vim_mode(if matches!(op, Operator::Change) {
                VimMode::Insert
            } else {
                VimMode::Normal
            });
    }

    /// Apply `op` over the (exclusive) motion range from the cursor to the
    /// motion's landing point, block-aware. Yank copies; Delete/Change cut.
    /// Returns `true` when the motion covered a non-empty range.
    fn apply_operator_motion<F>(&mut self, op: Operator, motion: F) -> bool
    where
        F: FnOnce(&mut crate::tui::composer::Composer),
    {
        let from = self.composer.cursor();
        let to = self.composer.probe_motion(motion);
        if from == to {
            return false;
        }
        let (lo, hi) = if from <= to { (from, to) } else { (to, from) };
        self.apply_operator_range_no_mode(op, lo, hi);
        true
    }

    /// Like [`Self::apply_operator_motion`] but inclusive of the landing
    /// char (for `e`/`E`/`%` which land *on* the last char to operate on).
    fn apply_operator_motion_inclusive<F>(&mut self, op: Operator, motion: F) -> bool
    where
        F: FnOnce(&mut crate::tui::composer::Composer),
    {
        let from = self.composer.cursor();
        let to = self.composer.probe_motion(motion);
        if from == to {
            return false;
        }
        let (lo, hi) = if from <= to {
            // Include the char at `to`.
            let hi = self
                .composer
                .text()
                .get(to..)
                .and_then(|s| s.chars().next())
                .map(|c| to + c.len_utf8())
                .unwrap_or(to);
            (from, hi)
        } else {
            (to, from)
        };
        self.apply_operator_range_no_mode(op, lo, hi);
        true
    }

    /// Apply `op` over an explicit byte range `[lo, hi)`, then set the
    /// post-op vim mode. Used by the find/text-object operator paths
    /// (always charwise — linewise only arises from `dd`/`cc`/`yy` and
    /// visual-line, handled elsewhere).
    fn apply_operator_range(&mut self, op: Operator, lo: usize, hi: usize) {
        if lo < hi {
            self.apply_operator_range_no_mode(op, lo, hi);
        }
        self.finish_operator(op);
    }

    /// Apply `op` over `[lo, hi)` without touching the vim mode. Widens to
    /// swallow any paste block the range crosses (atomic blocks) and keeps
    /// the registry in sync. Yank copies into the register + clipboard;
    /// Delete/Change cut into the register + clipboard.
    fn apply_operator_range_no_mode(&mut self, op: Operator, mut lo: usize, mut hi: usize) {
        if let Some((bs, be)) = self.paste_registry.block_crossed_by(lo, hi) {
            lo = lo.min(bs);
            hi = hi.max(be);
        }
        match op {
            Operator::Yank => {
                self.composer.yank_range(lo, hi, false);
                // Cursor goes to the start of a yank (vim).
                self.composer.set_cursor(lo);
            }
            Operator::Delete | Operator::Change => {
                self.composer.cut_range(lo, hi, false);
                self.paste_registry
                    .shift_for_edit(lo, -((hi - lo) as isize));
            }
        }
        self.mirror_register_to_clipboard();
    }

    pub(super) fn complete_or_submit(&mut self) -> bool {
        // Shell mode: a leading `!` runs the rest as a one-shot local
        // command (GOALS §1k). Never reaches the agent or the wire.
        if self.composer.text().starts_with('!') {
            let cmd = self.composer.text()[1..].to_string();
            self.composer.clear();
            self.paste_registry.clear();
            self.run_shell_command(&cmd);
            self.at_dismissed = false;
            self.at_selected = 0;
            self.at_scroll = 0;
            if self.composer.vim_enabled() {
                self.composer.set_vim_mode(VimMode::Insert);
            }
            return false;
        }
        if let Some(query) = self.slash_query() {
            if let Some(command) = super::hidden_slash_alias(query) {
                return self.execute_slash(command);
            }
            // Run whatever is highlighted. The default highlight is the
            // frequency-ranked top match (index 0), so `/foo`+Enter still
            // runs the top match — preserving the pre-cursor muscle memory.
            // A bare skill entry (`/<skill-name>`) seeds a deterministic skill
            // invocation; a builtin dispatches as usual
            // (implementation note).
            // Resolve the highlighted entry to an owned form first so the
            // `self`-borrow from `slash_suggestions` (it references
            // `self.skill_commands`) is released before the `&mut self`
            // dispatch.
            let chosen: Option<Result<super::SlashCommand, String>> = {
                let matches = self.slash_suggestions();
                if matches.is_empty() {
                    None
                } else {
                    let idx = self.slash_selected.min(matches.len() - 1);
                    Some(match matches[idx] {
                        super::SlashEntry::Builtin(cmd) => Ok(*cmd),
                        super::SlashEntry::Skill(s) => Err(s.name.clone()),
                    })
                }
            };
            return match chosen {
                None => false,
                Some(Ok(cmd)) => self.execute_slash(cmd),
                Some(Err(name)) => self.invoke_skill_slash(&name),
            };
        }
        self.submit_input()
    }

    pub(super) fn submit_input(&mut self) -> bool {
        // Daemon draining (`daemon-graceful-drain-shutdown.md`): refuse new
        // input with a short notice rather than dropping or queuing it. The
        // composer keeps the user's text so they can copy it out before the
        // process exits.
        if self.daemon_draining {
            self.show_toast(
                "daemon is shutting down — not accepting new messages",
                super::ToastKind::Error,
            );
            return false;
        }

        // The *displayed* message keeps the composer's exact text,
        // including paste-block placeholders (wire/user split — the user
        // sees `[Pasted text #1, …]`, the model gets the expansion).
        let submitted = self.composer.text().trim().to_string();
        if submitted.is_empty() && self.paste_registry.is_empty() {
            return false;
        }

        // Build the paste-side wire from the live (untrimmed) buffer +
        // registry: text blocks inline their full content; image blocks
        // become real image parts on a vision model, or a terse text note
        // otherwise. `paste_images` are the ordered PNG payloads; the
        // sentinel markers in `paste_wire` mark where each lands. Done
        // first (offsets index the untrimmed buffer) and gated on the
        // active model's `inputs.images` at *this* send time — a `/model`
        // switch since paste round-trips the same blocks differently.
        let vision = self.active_model_supports_images();
        let (paste_wire, paste_images) =
            self.paste_registry.build_wire(self.composer.text(), vision);
        let paste_wire = paste_wire.trim().to_string();
        if paste_wire.is_empty() && paste_images.is_empty() {
            return false;
        }
        if let Err(message) = validate_pasted_images_for_submit(&paste_images) {
            self.show_toast(message, super::ToastKind::Error);
            return false;
        }
        self.lock_pending_agent_switch_log();

        // `/compact` review-then-commit (T6.e): the composer holds the
        // assembled handoff (user may have edited it). On submit, re-attach
        // to the fresh session the daemon created and send the handoff as
        // its first message. The old session stays whole in SQLite,
        // recoverable via `cockpit session show/resume`.
        if self.pending_compact.is_some() {
            return self.commit_compact(submitted);
        }

        // Submitting a new turn implies the user has finished reading
        // history — jump back to the live tail so they see the reply.
        self.chat_scroll_offset = 0;

        // Expand any `@path[:range]` tags into fenced file/dir blocks
        // before dispatch (GOALS §1e). The displayed user message keeps
        // the original `@`-form; only the wire payload gets inlined.
        // Autocompleted spaced paths are quoted on this submit copy so
        // the scanner reads them as one token (the composer stays clean).
        // Tag expansion runs over the paste-expanded wire so a tag and a
        // pasted block can coexist in one message.
        let quoted = crate::tui::file_tag::quote_tracked_tags(&paste_wire, &self.accepted_tags);
        let mut allow = crate::config::extended::resolve_gitignore_allow(&self.launch.cwd);
        allow.extend(self.gitignore_session_allow.clone());
        let tag_policy =
            crate::tui::file_tag::TagPolicy::new_for_mode(&self.launch.cwd, allow, self.llm_mode);
        let expanded = crate::tui::file_tag::expand_tags_with_policy(&quoted, &tag_policy);
        // Attach any buffered `/git` blocks to this message's wire text
        // (GOALS §1l). The displayed user message keeps the original
        // text (wire/user split); only the agent-bound wire carries the
        // block, so it flows through `redact::scrub` like any wire text.
        let wire = if self.pending_git_blocks.is_empty() {
            expanded.wire
        } else {
            let blocks = std::mem::take(&mut self.pending_git_blocks).join("\n\n");
            if expanded.wire.is_empty() {
                blocks
            } else {
                format!("{}\n\n{}", expanded.wire, blocks)
            }
        };
        // Per-tag entries are surfaced as harness-automatic tool calls in
        // the chat (GOALS §1e); the agent didn't invoke them, the
        // composer did. Cleared the accepted-tags tracker now that the
        // submit copy has consumed it.
        self.accepted_tags.clear();

        // If a turn is in flight, the daemon will queue this message
        // and fold it into the next inference call (GOALS §1c). Track
        // it locally so the user sees what's pending; cleared when the
        // daemon emits `ThinkingStarted` (its drain signal). We gate on
        // the span-long `busy` state rather than `pending.is_some()`:
        // the latter drops to `None` between tool rounds, so a message
        // typed during tool execution would otherwise be mistaken for a
        // fresh turn.
        // True only on the fresh-submit path: this submit owns the
        // rising edge of the working span and must undo it if the turn
        // can't be handed off. The busy/queue path didn't start a span,
        // so it must never tear one down.
        let was_busy = self.busy;
        let fresh_tag_expansions = if was_busy {
            self.queue.push(optimistic_queue_item(submitted.clone()));
            // Defer the tool-call entries so they render right after the
            // folded user message (on the next `ThinkingStarted`).
            self.queued_tag_batches.push(expanded.expansions);
            Vec::new()
        } else {
            // Fresh human message: start a new working span (resets the
            // cumulative clock and re-rolls the working line) and render
            // as the user's turn immediately.
            self.begin_working_span();

            // Track for Up/Down history navigation.
            self.prompt_history.push(submitted.clone());
            self.prompt_history_cursor = 0;
            self.staged_draft = None;
            expanded.expansions
        };
        let owns_working_span = !was_busy;

        // Carry the wire text together with any real image parts (vision
        // only — non-vision folded the images into `wire` as text notes,
        // leaving `paste_images` empty).
        let submission = crate::engine::message::UserSubmission {
            kind: crate::engine::message::UserSubmissionKind::User,
            text: wire,
            images: paste_images,
            forced_skill: None,
            origin_principal: None,
            job_id: None,
            preflight_cleaned: None,
            queue_item_ids: Vec::new(),
            queue_target: None,
        };

        if owns_working_span {
            self.dispatch_optimistic_user_submission(
                submitted.clone(),
                submission,
                "engine",
                true,
                &fresh_tag_expansions,
            );
        } else {
            self.ensure_agent_runner();
            match self.agent_runner.as_ref() {
                Some(Ok(runner)) => {
                    if runner.input_tx.try_send(submission).is_err() {
                        let summary = "engine: queued message could not be sent".to_string();
                        self.history.push(HistoryEntry::InferenceError {
                            detail: summary.clone(),
                            summary,
                            expanded: false,
                        });
                    }
                }
                Some(Err(_)) | None => {
                    let summary = "engine: queued message could not be sent".to_string();
                    self.history.push(HistoryEntry::InferenceError {
                        detail: summary.clone(),
                        summary,
                        expanded: false,
                    });
                }
            }
        }
        self.composer.clear();
        // The buffer is gone — its paste blocks go with it.
        self.paste_registry.clear();
        self.at_dismissed = false;
        self.at_selected = 0;
        self.at_scroll = 0;
        // Re-enter Normal mode on submit when vim is enabled, so the
        // composer is ready to be navigated without typing into it.
        // Mirror Insert otherwise.
        if self.composer.vim_enabled() {
            self.composer.set_vim_mode(VimMode::Insert);
        }
        false
    }

    /// Whether a just-closed question dialog `result` is the local
    /// `/init` existing-file prompt (matched by the pending init's
    /// synthetic interrupt id) rather than a real daemon interrupt.
    fn init_choice_for(&self, result: &crate::tui::dialog::question::QuestionResult) -> bool {
        use crate::tui::dialog::question::QuestionResult;
        let id = match result {
            QuestionResult::Submit { interrupt_id, .. }
            | QuestionResult::Cancel { interrupt_id } => *interrupt_id,
        };
        self.pending_init
            .as_ref()
            .is_some_and(|p| p.interrupt_id == id)
    }

    fn paused_work_choice_for(
        &self,
        result: &crate::tui::dialog::question::QuestionResult,
    ) -> bool {
        use crate::tui::dialog::question::QuestionResult;
        let id = match result {
            QuestionResult::Submit { interrupt_id, .. }
            | QuestionResult::Cancel { interrupt_id } => *interrupt_id,
        };
        self.pending_paused_work
            .as_ref()
            .is_some_and(|p| p.interrupt_id == id)
    }

    fn resume_repair_choice_for(
        &self,
        result: &crate::tui::dialog::question::QuestionResult,
    ) -> bool {
        use crate::tui::dialog::question::QuestionResult;
        let id = match result {
            QuestionResult::Submit { interrupt_id, .. }
            | QuestionResult::Cancel { interrupt_id } => *interrupt_id,
        };
        self.pending_resume_repair
            .as_ref()
            .is_some_and(|p| p.interrupt_id == id)
    }

    /// Whether a just-closed question dialog `result` is the local bare
    /// `/toggle-redaction` multiselect (matched by the pending toggle's
    /// synthetic interrupt id) rather than a real daemon interrupt.
    fn redaction_toggle_choice_for(
        &self,
        result: &crate::tui::dialog::question::QuestionResult,
    ) -> bool {
        use crate::tui::dialog::question::QuestionResult;
        let id = match result {
            QuestionResult::Submit { interrupt_id, .. }
            | QuestionResult::Cancel { interrupt_id } => *interrupt_id,
        };
        self.pending_redaction_toggle == Some(id)
    }

    /// Whether a just-closed question dialog `result` is the local
    /// `/model-comparison` multiselect (matched by the pending select's
    /// synthetic interrupt id) rather than a real daemon interrupt.
    fn tandem_select_choice_for(
        &self,
        result: &crate::tui::dialog::question::QuestionResult,
    ) -> bool {
        use crate::tui::dialog::question::QuestionResult;
        let id = match result {
            QuestionResult::Submit { interrupt_id, .. }
            | QuestionResult::Cancel { interrupt_id } => *interrupt_id,
        };
        self.pending_tandem_select == Some(id)
    }
}

impl App {
    pub(super) fn find_owns_bottom_row(&self) -> bool {
        self.transcript_find.is_some()
    }

    fn open_transcript_find(&mut self) {
        self.selection = None;
        self.transcript_find = Some(TranscriptFind {
            saved_offset: self.chat_scroll_offset,
            ..TranscriptFind::default()
        });
    }

    fn close_transcript_find_restore(&mut self) {
        if let Some(find) = self.transcript_find.take() {
            self.chat_scroll_offset = find.saved_offset;
        }
    }

    fn close_transcript_find_keep_position(&mut self) {
        self.transcript_find = None;
    }

    fn handle_transcript_find_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press && key.kind != KeyEventKind::Repeat {
            return;
        }
        match key.code {
            KeyCode::Esc => self.close_transcript_find_restore(),
            KeyCode::Enter => {
                let should_keep = self
                    .transcript_find
                    .as_ref()
                    .is_some_and(|find| !find.query.is_empty() && find.current.is_some());
                if should_keep {
                    self.close_transcript_find_keep_position();
                } else {
                    self.close_transcript_find_restore();
                }
            }
            KeyCode::Char('f')
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::SHIFT) =>
            {
                self.close_transcript_find_keep_position();
            }
            KeyCode::Backspace => {
                if let Some(find) = self.transcript_find.as_mut() {
                    find.query.pop();
                }
                self.recompute_transcript_find();
            }
            KeyCode::Down | KeyCode::Tab => self.cycle_transcript_find(1),
            KeyCode::Up | KeyCode::BackTab => self.cycle_transcript_find(-1),
            KeyCode::Char('n')
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::SHIFT) =>
            {
                self.cycle_transcript_find(1);
            }
            KeyCode::Char('p')
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::SHIFT) =>
            {
                self.cycle_transcript_find(-1);
            }
            KeyCode::Char(ch)
                if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
            {
                if let Some(find) = self.transcript_find.as_mut() {
                    find.query.push(normalize_shift_char(&key, ch));
                }
                self.recompute_transcript_find();
            }
            _ => {}
        }
    }

    fn recompute_transcript_find(&mut self) {
        let top = self.visible_chat_top_line();
        let Some(find) = self.transcript_find.as_mut() else {
            return;
        };
        find.matches.clear();
        find.current = None;
        if find.query.is_empty() {
            return;
        }
        let query = find.query.to_lowercase();
        find.matches = self
            .chat_find_lines
            .iter()
            .enumerate()
            .filter_map(|(idx, line)| line.to_lowercase().contains(&query).then_some(idx))
            .collect();
        if find.matches.is_empty() {
            return;
        }
        let current = find
            .matches
            .iter()
            .position(|line| *line >= top)
            .unwrap_or(0);
        find.current = Some(current);
        let abs = find.matches[current];
        self.scroll_abs_line_into_view(abs);
    }

    fn cycle_transcript_find(&mut self, delta: isize) {
        let Some(find) = self.transcript_find.as_mut() else {
            return;
        };
        let len = find.matches.len();
        if len == 0 {
            return;
        }
        let current = find.current.unwrap_or(0);
        let next = if delta >= 0 {
            (current + 1) % len
        } else {
            (current + len - 1) % len
        };
        find.current = Some(next);
        let abs = find.matches[next];
        self.scroll_abs_line_into_view(abs);
    }

    fn visible_chat_top_line(&self) -> usize {
        self.chat_total_lines
            .saturating_sub(self.chat_visible_lines.max(1))
            .saturating_sub(self.chat_scroll_offset)
    }
}

enum QueueEditOutcome {
    Edited { text: String, partial: bool },
    AlreadyStarted,
    Unavailable,
}

impl App {
    fn edit_queued_messages(&mut self) {
        match self.remove_editable_queued_messages() {
            QueueEditOutcome::Edited { text, partial } => {
                self.composer.set(text);
                self.paste_registry.clear();
                if partial {
                    self.push_queue_edit_notice("some queued messages already started");
                }
            }
            QueueEditOutcome::AlreadyStarted => {
                self.push_queue_edit_notice("queued message already started");
            }
            QueueEditOutcome::Unavailable => {
                self.push_queue_edit_notice("queued messages could not be edited");
            }
        }
    }

    fn push_queue_edit_notice(&mut self, text: &str) {
        self.show_toast(text, super::ToastKind::Info);
    }

    fn remove_editable_queued_messages(&mut self) -> QueueEditOutcome {
        let socket = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => runner.socket.clone(),
            _ => return QueueEditOutcome::Unavailable,
        };
        self.remove_editable_queued_messages_with(|| {
            crate::tui::agent_runner::daemon_request_at_blocking(
                &socket,
                Request::RemoveEditableQueuedUserMessages { target_id: None },
            )
        })
    }

    fn remove_editable_queued_messages_with<F>(&mut self, remove: F) -> QueueEditOutcome
    where
        F: FnOnce() -> Result<Response, String>,
    {
        match remove() {
            Ok(Response::RemoveQueuedUserMessagesResult {
                applied: true,
                reason,
                removed_items,
                queue,
            }) if !removed_items.is_empty() => {
                let removed_text = removed_items
                    .into_iter()
                    .map(|item| item.text)
                    .collect::<Vec<_>>()
                    .join("\n\n");
                self.replace_queue_from_proto(queue);
                QueueEditOutcome::Edited {
                    text: removed_text,
                    partial: matches!(reason, proto::RemoveQueuedUserMessageReason::AlreadyStarted),
                }
            }
            Ok(Response::RemoveQueuedUserMessagesResult { reason, queue, .. }) => {
                self.replace_queue_from_proto(queue);
                match reason {
                    proto::RemoveQueuedUserMessageReason::AlreadyStarted => {
                        QueueEditOutcome::AlreadyStarted
                    }
                    proto::RemoveQueuedUserMessageReason::NotFound => QueueEditOutcome::Unavailable,
                    proto::RemoveQueuedUserMessageReason::Removed => QueueEditOutcome::Unavailable,
                }
            }
            _ => QueueEditOutcome::Unavailable,
        }
    }

    fn replace_queue_from_proto(&mut self, queue: Vec<proto::QueueItem>) {
        let previous_queue = std::mem::take(&mut self.queue);
        let previous_batches = std::mem::take(&mut self.queued_tag_batches);
        let next_queue: Vec<_> = queue.into_iter().map(queue_item_from_proto).collect();
        let mut next_batches = Vec::with_capacity(next_queue.len());

        for item in &next_queue {
            let batch = previous_queue
                .iter()
                .position(|previous| previous.id == item.id)
                .and_then(|idx| previous_batches.get(idx).cloned())
                .unwrap_or_default();
            next_batches.push(batch);
        }

        self.queue = next_queue;
        self.queued_tag_batches = next_batches;
    }

    #[cfg(test)]
    pub(super) fn edit_queued_messages_for_test(&mut self, response: Response) {
        match self.remove_editable_queued_messages_with(|| Ok(response)) {
            QueueEditOutcome::Edited { text, partial } => {
                self.composer.set(text);
                self.paste_registry.clear();
                if partial {
                    self.push_queue_edit_notice("some queued messages already started");
                }
            }
            QueueEditOutcome::AlreadyStarted => {
                self.push_queue_edit_notice("queued message already started");
            }
            QueueEditOutcome::Unavailable => {
                self.push_queue_edit_notice("queued messages could not be edited");
            }
        }
    }
}

pub(super) fn optimistic_queue_item(text: String) -> QueuedUserMessage {
    QueuedUserMessage {
        id: uuid::Uuid::new_v4(),
        status: QueueItemStatus::Queued,
        text,
        target: crate::engine::message::QueueTarget::root(""),
    }
}

pub(super) fn queue_item_from_proto(item: proto::QueueItem) -> QueuedUserMessage {
    QueuedUserMessage {
        id: item.id,
        status: match item.status {
            proto::QueueItemStatus::Queued => QueueItemStatus::Queued,
            proto::QueueItemStatus::Folding => QueueItemStatus::Folding,
        },
        text: item.text,
        target: crate::engine::message::QueueTarget {
            id: item.target.id,
            agent: item.target.agent,
            depth: item.target.depth,
            task_call_id: item.target.task_call_id,
        },
    }
}

/// The checked option ids from a closed `/toggle-redaction` multiselect, or
/// `None` on cancel (Esc). A confirm with nothing checked yields `Some(vec![])`
/// — "turn both sources off".
fn redaction_selected_ids(
    result: &crate::tui::dialog::question::QuestionResult,
) -> Option<Vec<String>> {
    use crate::daemon::proto::ResolveResponse;
    use crate::tui::dialog::question::QuestionResult;
    match result {
        QuestionResult::Submit { responses, .. } => match responses.first() {
            Some(ResolveResponse::Multi { selected_ids }) => Some(selected_ids.clone()),
            _ => Some(Vec::new()),
        },
        QuestionResult::Cancel { .. } => None,
    }
}

/// The chosen single-select option id from a closed `/init` prompt, or
/// `None` for cancel / a malformed response.
fn init_selected_id(result: &crate::tui::dialog::question::QuestionResult) -> Option<String> {
    use crate::daemon::proto::ResolveResponse;
    use crate::tui::dialog::question::QuestionResult;
    match result {
        QuestionResult::Submit { responses, .. } => match responses.first() {
            Some(ResolveResponse::Single { selected_id }) => Some(selected_id.clone()),
            _ => None,
        },
        QuestionResult::Cancel { .. } => None,
    }
}

impl App {
    // ---- Paste blocks (composer-paste-handling) -----------------------
    //
    // A genuine bracketed paste arrives as one `Event::Paste(String)`.
    // Images come from the system clipboard read on the same gesture. Both
    // collapse into atomic placeholder blocks tracked in
    // `self.paste_registry`, kept byte-range-synced with the composer.

    /// Route a bracketed-paste event. First checks the clipboard for an
    /// image (a paste gesture over an image puts the bytes there, while
    /// `data` is typically empty or a filename); if present, inserts an
    /// image block. Otherwise treats `data` as text: re-paste-to-expand
    /// if the cursor sits at a matching text block's right edge, else
    /// condense-or-insert by the threshold rule.
    pub(super) fn handle_paste(&mut self, data: String) {
        // Route the paste the same way typed keys are routed (see
        // `handle_key`): a focused embedded PTY owns terminal input and
        // consumes paste before the composer/image clipboard path. If the
        // pane is open but not focused, app-owned fields still receive paste.
        if self.pane_focused && self.pane.is_some() {
            if let Some(pane) = self.pane.as_mut() {
                pane.forward_paste(&data);
            }
            return;
        }
        if self.daemon_prompt.is_some()
            || self.stats_pane.is_some()
            || self.usage_pane.is_some()
            || self.sessions_pane.is_some()
            || self.skills_pane.is_some()
            || self.permissions_pane.is_some()
            || self.resources_pane.is_some()
            || self.quick_dialog.is_some()
            || self.context_pane.is_some()
            || self.diff_pane.is_some()
            || self.context_menu.is_some()
            || self.pin_pick.is_some()
            || self.fork_pick.is_some()
            || self.copy_pick.is_some()
            || self.pins_review.is_some()
            || self.keys_overlay.is_some()
            || self.transcript_find.is_some()
        {
            return;
        }
        // Text-field-owning overlays, in the same precedence as `handle_key`:
        // answering dialog → settings dialog → model picker. Each routes the
        // paste to whichever of its fields is focused (or drops it when none
        // is). The "which field is focused" logic stays inside each component.
        if let Some(dialog) = self.question_dialog.as_mut() {
            dialog.paste(&data);
            return;
        }
        if self.dialog.is_active() {
            self.dialog.paste(&data);
            return;
        }
        if let Some(picker) = self.model_picker.as_mut() {
            picker.paste(&data);
            return;
        }
        if let Some(dialog) = self.multireview_dialog.as_mut() {
            dialog.paste(&data);
            return;
        }
        if let Some(pane) = self.notes_pane.as_mut() {
            pane.paste(&data);
            return;
        }

        // Image first: a clipboard image on the paste gesture becomes an
        // image block regardless of `data`. SSH is out of scope — the read
        // is local-clipboard only and silently yields `None` when there's
        // no bitmap.
        match crate::clipboard::read_image_as_png() {
            Ok(Some(png)) => {
                self.insert_image_block(png);
                return;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!(error = %e, "clipboard image read failed; treating paste as text");
            }
        }

        if data.is_empty() {
            return;
        }

        // Re-paste-to-expand: cursor at a text block's right edge + the
        // paste equals that block's stored content → expand in place.
        let cursor = self.composer.cursor();
        if let Some((start, end, full)) = self.paste_registry.expandable_text_at(cursor, &data) {
            // Replace the placeholder span with the raw text and drop the
            // block from the registry.
            self.composer.delete_range(start, end);
            self.paste_registry.remove_range(start, end);
            self.composer.set_cursor(start);
            self.insert_text_raw(&full);
            self.refresh_at_dismiss();
            self.reset_at_window();
            self.reset_slash_window();
            return;
        }

        if crate::tui::paste::should_condense(&data) {
            self.insert_text_block(data);
        } else {
            self.insert_text_raw(&data);
        }
        self.refresh_at_dismiss();
        self.reset_at_window();
        self.reset_slash_window();
    }

    /// Insert raw (non-condensed) pasted text at the cursor, snapping the
    /// insertion point to a block boundary first and shifting the registry
    /// for the inserted length.
    fn insert_text_raw(&mut self, text: &str) {
        let at = self
            .paste_registry
            .resolve_insertion(self.composer.cursor());
        self.composer.set_cursor(at);
        self.composer.insert_str(text);
        self.paste_registry.shift_for_edit(at, text.len() as isize);
    }

    /// Estimate tokens for a condensed text block: the active model's
    /// calibrated counter when available, else cl100k_base (GOALS §10
    /// fallback). v1 has no in-TUI calibrated counter wired, so this is
    /// cl100k today — the seam is here for when one lands.
    fn estimate_paste_tokens(&self, text: &str) -> usize {
        crate::tokens::count(text)
    }

    /// Condense a long text paste into a `[Pasted text #N, X tokens]`
    /// block. The placeholder occupies the buffer; the full text lives in
    /// the registry and is inlined at send time.
    fn insert_text_block(&mut self, full: String) {
        let at = self
            .paste_registry
            .resolve_insertion(self.composer.cursor());
        self.composer.set_cursor(at);
        let tokens = self.estimate_paste_tokens(&full);
        let placeholder = self.paste_registry.register_text(at, full, tokens);
        self.composer.insert_str(&placeholder);
        // `register_text` already recorded the block at `[at, at+len)`;
        // shift only the blocks that were *after* the insertion point.
        self.shift_other_blocks_after_insert(at, placeholder.len());
    }

    /// Insert a pasted image as a `[Pasted image #N]` block. On a
    /// non-vision model, also toast that it'll be sent as a text note —
    /// the bytes are retained either way and re-evaluated at send time.
    fn insert_image_block(&mut self, png: Vec<u8>) {
        let at = self
            .paste_registry
            .resolve_insertion(self.composer.cursor());
        self.composer.set_cursor(at);
        let placeholder = self.paste_registry.register_image(at, png);
        self.composer.insert_str(&placeholder);
        self.shift_other_blocks_after_insert(at, placeholder.len());
        self.refresh_at_dismiss();
        self.reset_at_window();
        self.reset_slash_window();
        if !self.active_model_supports_images() {
            self.show_toast(
                "Current model has no image support — this image will be sent as a text note.",
                super::ToastKind::Info,
            );
        }
    }

    /// After [`crate::tui::paste::PasteRegistry::register_text`] /
    /// `register_image` recorded a new block at `[at, at+len)`, shift the
    /// *other* blocks that started at/after `at` (the new one is exact).
    /// `register_*` inserts the new block sorted, so we shift every block
    /// whose start is `> at` (i.e. excluding the one we just added).
    fn shift_other_blocks_after_insert(&mut self, at: usize, len: usize) {
        for b in self.paste_registry.blocks_mut() {
            if b.start > at {
                b.start += len;
                b.end += len;
            }
        }
    }

    /// Whether the active model accepts real image parts
    /// (`inputs.images: true`). Recomputed by `reload_launch_info` after a
    /// `/model` switch, so images round-trip without a re-paste.
    pub(super) fn active_model_supports_images(&self) -> bool {
        self.launch.active_model_supports_images
    }

    /// `dd` — delete the current line, block-aware. Any paste block on
    /// that line is removed whole (the whole line goes), and the registry
    /// is reconciled for the removed byte range. The line's byte range is
    /// computed up front (start of the line through its trailing `\n`, or
    /// the preceding `\n` on the last line) so we can shift the registry
    /// by the exact removed extent before delegating to the composer.
    fn delete_current_line_block_aware(&mut self) {
        if self.paste_registry.is_empty() {
            self.composer.delete_current_line();
            return;
        }
        let before = self.composer.len();
        let cursor = self.composer.cursor();
        let text = self.composer.text();
        let line_start = text[..cursor].rfind('\n').map(|i| i + 1).unwrap_or(0);
        self.composer.delete_current_line();
        let removed = before - self.composer.len();
        if removed > 0 {
            // `delete_current_line` removes either `[line_start, …]` or,
            // on the last line, `[line_start-1, …]`. The lower anchor is
            // the smaller of the original line start and the post-delete
            // cursor (which lands at the new line's start).
            let anchor = line_start.min(self.composer.cursor());
            self.paste_registry
                .shift_for_edit(anchor, -(removed as isize));
        }
    }

    /// Block whose closing `]` is exactly at the cursor (Backspace
    /// whole-block delete). Mirrors `completed_tag_left` for `@`-tags.
    fn paste_block_left(&self) -> Option<(usize, usize)> {
        self.paste_registry
            .block_ending_at(self.composer.cursor())
            .map(|b| (b.start, b.end))
    }

    /// Block whose opening `[` is exactly at the cursor (forward-`Delete`
    /// whole-block delete). Mirrors `completed_tag_right`.
    fn paste_block_right(&self) -> Option<(usize, usize)> {
        self.paste_registry
            .block_starting_at(self.composer.cursor())
            .map(|b| (b.start, b.end))
    }

    /// Delete the block at `[start, end)` from both the buffer and the
    /// registry, leaving the cursor at `start`.
    fn delete_paste_block(&mut self, start: usize, end: usize) {
        self.composer.delete_range(start, end);
        self.paste_registry.remove_range(start, end);
    }

    /// Apply a Tab press to the pending ghost prediction
    /// (implementation note). The first Tab of a multi-line
    /// `long` prediction expands the ghost in place (box grows, still
    /// grey); otherwise the ghost converts to real editable text (fills,
    /// does NOT send). A `Fill` consumes the ghost and clears the cache so
    /// the now-real text is never re-offered as a ghost.
    pub(super) fn accept_prediction_ghost(&mut self) {
        use crate::tui::composer::GhostAccept;
        let Some(ghost) = self.prediction_state.ghost_mut() else {
            return;
        };
        match ghost.accept() {
            GhostAccept::Expand => {
                // Stays a ghost; the renderer + box height read the new
                // (full) stage off the ghost.
            }
            GhostAccept::Fill(text) => {
                self.composer.set(text);
                self.paste_registry.clear();
                // Consume the ghost + its cache: the text is real now, and
                // clearing the box later must not restore this prediction
                // (the user has acted on it).
                self.prediction_state.consume();
            }
        }
    }

    /// Insert one char, block-aware. Fast-paths to the plain composer
    /// insert when no blocks exist (so ordinary typing is byte-identical
    /// to today). Otherwise snaps the insertion point out of any block
    /// interior and shifts trailing block ranges.
    fn composer_insert_char(&mut self, ch: char) {
        if self.paste_registry.is_empty() {
            self.composer.insert_char(ch);
            return;
        }
        let at = self
            .paste_registry
            .resolve_insertion(self.composer.cursor());
        self.composer.set_cursor(at);
        self.composer.insert_char(ch);
        self.paste_registry
            .shift_for_edit(at, ch.len_utf8() as isize);
    }

    /// Backspace, block-aware. (The whole-block case is handled by the
    /// caller via `paste_block_left`; this is the ordinary single-char
    /// path.) Snaps the cursor off a left boundary first so a Backspace
    /// just *inside* the text after a block can't reach into it, then
    /// shifts trailing blocks for the removed byte.
    fn composer_delete_left(&mut self) {
        if self.paste_registry.is_empty() {
            self.composer.delete_left();
            return;
        }
        let cursor = self.composer.cursor();
        // Never delete from inside a block interior — snap to its start.
        let cursor = self.paste_registry.skip_cursor(cursor, false);
        self.composer.set_cursor(cursor);
        let before = self.composer.len();
        self.composer.delete_left();
        let removed = before - self.composer.len();
        if removed > 0 {
            // delete_left removes the char ending at the old cursor; the
            // edit anchor is the new cursor position.
            self.paste_registry
                .shift_for_edit(self.composer.cursor(), -(removed as isize));
        }
    }

    /// Forward-delete (`Delete` / vim `x`), block-aware ordinary-char
    /// path. The whole-block case is handled by `paste_block_right`.
    fn composer_delete_right(&mut self) {
        if self.paste_registry.is_empty() {
            self.composer.delete_right();
            return;
        }
        let cursor = self.composer.cursor();
        let cursor = self.paste_registry.skip_cursor(cursor, true);
        self.composer.set_cursor(cursor);
        let at = self.composer.cursor();
        let before = self.composer.len();
        self.composer.delete_right();
        let removed = before - self.composer.len();
        if removed > 0 {
            self.paste_registry.shift_for_edit(at, -(removed as isize));
        }
    }

    /// Run a vim normal-mode motion (`w`/`W`/`b`/`B`) then snap the cursor
    /// off any block interior to the far boundary in the direction of
    /// travel (`forward`), so a word motion treats a paste block as one
    /// unit. Fast-paths when there are no blocks.
    fn vim_motion<F: FnOnce(&mut crate::tui::composer::Composer)>(
        &mut self,
        motion: F,
        forward: bool,
    ) {
        motion(&mut self.composer);
        if self.paste_registry.is_empty() {
            return;
        }
        let landed = self
            .paste_registry
            .skip_cursor(self.composer.cursor(), forward);
        self.composer.set_cursor(landed);
    }

    /// Move left one unit, treating a block as a single step: landing on a
    /// block's right boundary then moving left jumps to its left boundary.
    fn composer_move_left(&mut self) {
        if self.paste_registry.is_empty() {
            self.composer.move_left();
            return;
        }
        let cursor = self.composer.cursor();
        // If we're exactly at a block's right edge, jump the whole block.
        if let Some(b) = self.paste_registry.block_ending_at(cursor) {
            self.composer.set_cursor(b.start);
            return;
        }
        self.composer.move_left();
        // If the plain move landed inside a block, snap to its start.
        let landed = self
            .paste_registry
            .skip_cursor(self.composer.cursor(), false);
        self.composer.set_cursor(landed);
    }

    /// Move right one unit, treating a block as a single step.
    fn composer_move_right(&mut self) {
        if self.paste_registry.is_empty() {
            self.composer.move_right();
            return;
        }
        let cursor = self.composer.cursor();
        if let Some(b) = self.paste_registry.block_starting_at(cursor) {
            self.composer.set_cursor(b.end);
            return;
        }
        self.composer.move_right();
        let landed = self
            .paste_registry
            .skip_cursor(self.composer.cursor(), true);
        self.composer.set_cursor(landed);
    }

    /// Run a vim motion-delete (`dw`, `db`, `cw`, `d$`, `d0`, `dG`,
    /// `dgg`, …) block-aware via a motion closure that moves the composer
    /// cursor to the far end of the operator's range and a matching plain
    /// `delete` closure for the no-blocks fast path. When blocks exist, we
    /// delete the byte span between the start and the motion's landing
    /// point, widened to a block boundary if it crosses any paste block,
    /// so the block is removed whole. When no blocks exist we just run the
    /// plain composer delete — vim editing is byte-identical to today.
    fn block_aware_delete<M, D>(&mut self, motion: M, delete: D)
    where
        M: FnOnce(&mut crate::tui::composer::Composer),
        D: FnOnce(&mut crate::tui::composer::Composer),
    {
        if self.paste_registry.is_empty() {
            delete(&mut self.composer);
            return;
        }
        let from = self.composer.cursor();
        let to = self.composer.probe_motion(motion);
        if from == to {
            return;
        }
        let (mut lo, mut hi) = if from <= to { (from, to) } else { (to, from) };
        // Widen the range to swallow any block it crosses, so a delete
        // that touches a placeholder removes the whole block.
        if let Some((bs, be)) = self.paste_registry.block_crossed_by(lo, hi) {
            lo = lo.min(bs);
            hi = hi.max(be);
        }
        self.composer.delete_range(lo, hi);
        self.paste_registry
            .shift_for_edit(lo, -((hi - lo) as isize));
    }

    /// Run a `f`/`F`/`t`/`T` find as a standalone Normal-mode motion,
    /// then snap off any block interior in the direction of travel.
    fn vim_find_motion(&mut self, spec: FindSpec) {
        self.composer.apply_find(spec, true);
        self.snap_off_block(spec.forward);
    }

    /// After a cursor jump (find/`;`/`,`), snap off any paste-block
    /// interior to the far boundary in the direction of travel.
    fn snap_off_block(&mut self, forward: bool) {
        if self.paste_registry.is_empty() {
            return;
        }
        let landed = self
            .paste_registry
            .skip_cursor(self.composer.cursor(), forward);
        self.composer.set_cursor(landed);
    }

    /// vim `x` — forward-delete one char into the register (charwise).
    /// The block case is handled by the caller (`paste_block_right`).
    fn vim_cut_char_forward(&mut self) {
        let from = self.composer.cursor();
        let Some(ch) = self.composer.text()[from..].chars().next() else {
            return;
        };
        if ch == '\n' {
            return;
        }
        let hi = from + ch.len_utf8();
        // Yank the char and remove it, block-aware via the registry.
        self.composer.cut_range(from, hi, false);
        if !self.paste_registry.is_empty() {
            self.paste_registry
                .shift_for_edit(from, -((hi - from) as isize));
        }
        self.mirror_register_to_clipboard();
    }

    /// vim `p` (`after = true`) / `P` (`after = false`). Pulls the OS
    /// clipboard into the register first when it differs (so an external
    /// copy is pasteable), then inserts the register as ordinary buffer
    /// text and reconciles the paste registry for the inserted span.
    fn vim_paste(&mut self, after: bool) {
        self.sync_register_from_clipboard();
        if self.composer.register().text.is_empty() {
            return;
        }
        let before_len = self.composer.len();
        let before_cursor = self.composer.cursor();
        // The composer's paste lands relative to the cursor; snap the
        // cursor off any block interior first so we never insert inside a
        // block. (`p` inserts after the cursor cell — a block right edge
        // is a valid landing; `P` inserts before — a block left edge is.)
        if !self.paste_registry.is_empty() {
            let snapped = self.paste_registry.skip_cursor(before_cursor, after);
            self.composer.set_cursor(snapped);
        }
        // Record the insertion anchor: `p` inserts after the cursor cell,
        // `P` at the cursor. We compute it the same way the composer does
        // so the registry shift matches.
        let cursor = self.composer.cursor();
        let reg = self.composer.register().clone();
        let anchor = if reg.linewise {
            // Linewise inserts at a line boundary; compute it for the shift.
            if after {
                self.composer.text()[cursor..]
                    .find('\n')
                    .map(|i| cursor + i + 1)
                    .unwrap_or(self.composer.len())
            } else {
                self.composer.text()[..cursor]
                    .rfind('\n')
                    .map(|i| i + 1)
                    .unwrap_or(0)
            }
        } else if after {
            self.composer.text()[cursor..]
                .chars()
                .next()
                .map(|c| cursor + c.len_utf8())
                .unwrap_or(cursor)
        } else {
            cursor
        };
        if after {
            self.composer.paste_after();
        } else {
            self.composer.paste_before();
        }
        let inserted = self.composer.len() as isize - before_len as isize;
        if inserted > 0 && !self.paste_registry.is_empty() {
            self.paste_registry.shift_for_edit(anchor, inserted);
        }
    }

    /// Mirror the unnamed register to the system clipboard (best-effort).
    /// Called after every yank/delete/change so a yank is pasteable
    /// elsewhere. Failures are silent — the internal register still works.
    fn mirror_register_to_clipboard(&self) {
        let text = &self.composer.register().text;
        if text.is_empty() {
            return;
        }
        let _ = crate::clipboard::copy_plain(text);
    }

    /// Pull the OS clipboard into the register when it differs from the
    /// register's current text, so an external copy pastes with `p`/`P`.
    /// A read that matches the register (the common case right after a
    /// yank) leaves the linewise flag intact. SSH / failure is silent.
    fn sync_register_from_clipboard(&mut self) {
        let os = match crate::clipboard::read_text() {
            Ok(Some(t)) => t,
            _ => return,
        };
        if os.is_empty() || os == self.composer.register().text {
            return;
        }
        // External text — treat as charwise unless it's clearly a set of
        // whole lines (ends with `\n`), matching vim's clipboard semantics.
        let linewise = os.ends_with('\n');
        self.composer.set_register(Register { text: os, linewise });
    }

    /// Visual-mode key handling: motions + text objects extend the
    /// selection; `d`/`x`/`c`/`y` act on it; `v`/`V` toggle/exit; `Esc`
    /// cancels. The selection span is `composer.visual_range()`.
    pub(super) fn handle_key_visual(&mut self, key: KeyEvent) -> bool {
        let mode = self.composer.vim_mode();
        // A pending find target inside visual mode.
        if let Some(mut spec) = self.composer.pending_find() {
            self.composer.set_pending_find(None);
            if let KeyCode::Char(ch) = key.code {
                spec.target = ch;
                self.composer.apply_find(spec, true);
                self.snap_off_block(spec.forward);
            }
            return false;
        }
        // A pending text-object selector inside visual mode: set the
        // selection to the object's range (anchor=start, cursor=last char).
        if let Some(around) = self.pending_text_object.take() {
            if let KeyCode::Char(obj) = key.code
                && let Some((lo, hi)) = self.composer.text_object_range(obj, around)
                && lo < hi
            {
                self.select_range(lo, hi);
            }
            return false;
        }
        match key.code {
            KeyCode::Esc => {
                self.composer.end_visual();
                self.clear_vim_transient_state();
            }
            KeyCode::Char('v') => {
                if mode == VimMode::Visual {
                    self.composer.end_visual();
                } else {
                    self.composer.set_vim_mode(VimMode::Visual);
                }
                self.composer.set_pending_g(false);
            }
            KeyCode::Char('V') => {
                if mode == VimMode::VisualLine {
                    self.composer.end_visual();
                } else {
                    self.composer.set_vim_mode(VimMode::VisualLine);
                }
                self.composer.set_pending_g(false);
            }
            KeyCode::Char('i') => {
                self.pending_text_object = Some(false);
                self.composer.set_pending_g(false);
            }
            KeyCode::Char('a') => {
                self.pending_text_object = Some(true);
                self.composer.set_pending_g(false);
            }
            KeyCode::Char('d') | KeyCode::Char('x') => {
                self.visual_operate(Operator::Delete);
            }
            KeyCode::Char('c') => {
                self.visual_operate(Operator::Change);
            }
            KeyCode::Char('y') => {
                self.visual_operate(Operator::Yank);
            }
            // Find prefixes.
            KeyCode::Char('f') => self.composer.set_pending_find(Some(find_spec(false, true))),
            KeyCode::Char('F') => self
                .composer
                .set_pending_find(Some(find_spec(false, false))),
            KeyCode::Char('t') => self.composer.set_pending_find(Some(find_spec(true, true))),
            KeyCode::Char('T') => self.composer.set_pending_find(Some(find_spec(true, false))),
            KeyCode::Char(';') => {
                self.composer.repeat_find(false);
                self.snap_off_block(true);
            }
            KeyCode::Char(',') => {
                self.composer.repeat_find(true);
                self.snap_off_block(false);
            }
            // Motions extend the selection (move the live cursor).
            KeyCode::Char('h') | KeyCode::Left => self.composer_move_left(),
            KeyCode::Char('l') | KeyCode::Right => self.composer_move_right(),
            KeyCode::Char('j') | KeyCode::Down => self.composer.move_down(),
            KeyCode::Char('k') | KeyCode::Up => self.composer.move_up(),
            KeyCode::Char('w') => self.vim_motion(|c| c.move_word_forward(false), true),
            KeyCode::Char('W') => self.vim_motion(|c| c.move_word_forward(true), true),
            KeyCode::Char('b') => self.vim_motion(|c| c.move_word_backward(false), false),
            KeyCode::Char('B') => self.vim_motion(|c| c.move_word_backward(true), false),
            KeyCode::Char('e') => self.vim_motion(|c| c.move_word_end(false), true),
            KeyCode::Char('E') => self.vim_motion(|c| c.move_word_end(true), true),
            KeyCode::Char('0') => self.composer.move_line_start(),
            KeyCode::Char('$') => self.composer.move_line_end(),
            KeyCode::Char('G') => self.composer.move_buffer_end(),
            KeyCode::Char('%') => self.vim_motion(|c| c.match_bracket(), true),
            KeyCode::Char('g') => {
                if self.composer.pending_g() {
                    self.composer.move_buffer_start();
                    self.composer.set_pending_g(false);
                } else {
                    self.composer.set_pending_g(true);
                }
            }
            _ => {
                self.composer.set_pending_g(false);
            }
        }
        false
    }

    /// Set the visual selection to span `[lo, hi)`: anchor at `lo`, cursor
    /// on the last char of the range (charwise) — used when a text object
    /// resolves the selection in visual mode.
    fn select_range(&mut self, lo: usize, hi: usize) {
        // Cursor lands on the last char of the range (charwise inclusive).
        let last = self.composer.text()[..hi]
            .char_indices()
            .next_back()
            .map(|(i, _)| i)
            .unwrap_or(lo);
        self.composer.set_visual_selection(lo, last);
    }

    /// Apply an operator to the current visual selection, then leave
    /// visual mode (Change enters Insert; otherwise Normal). Empty /
    /// zero-width selections are a clean no-op back to Normal.
    fn visual_operate(&mut self, op: Operator) {
        let linewise = self.composer.vim_mode() == VimMode::VisualLine;
        let Some((lo, hi)) = self.composer.visual_range() else {
            self.composer.end_visual();
            return;
        };
        if lo >= hi {
            self.composer.end_visual();
            return;
        }
        // Widen to swallow any block the selection crosses (atomic).
        let (mut lo, mut hi) = (lo, hi);
        if let Some((bs, be)) = self.paste_registry.block_crossed_by(lo, hi) {
            lo = lo.min(bs);
            hi = hi.max(be);
        }
        match op {
            Operator::Yank => {
                self.composer.yank_range(lo, hi, linewise);
                self.composer.set_cursor(lo);
                self.composer.set_vim_mode(VimMode::Normal);
            }
            Operator::Delete | Operator::Change => {
                self.composer.cut_range(lo, hi, linewise);
                self.paste_registry
                    .shift_for_edit(lo, -((hi - lo) as isize));
                self.composer
                    .set_vim_mode(if matches!(op, Operator::Change) {
                        VimMode::Insert
                    } else {
                        VimMode::Normal
                    });
            }
        }
        // Drop the anchor (we set the mode directly above, not via
        // end_visual, to preserve the Change→Insert transition).
        self.composer.clear_visual_anchor();
        self.mirror_register_to_clipboard();
    }

    pub(super) fn is_ctrl_shift_y(&self, key: &KeyEvent) -> bool {
        if !key.modifiers.contains(KeyModifiers::CONTROL) {
            return false;
        }
        match key.code {
            KeyCode::Char('Y') => true,
            KeyCode::Char('y') => key.modifiers.contains(KeyModifiers::SHIFT),
            _ => false,
        }
    }

    /// True when the key event represents `Ctrl+Shift+C`. Same shape
    /// dance as `is_ctrl_shift_y` (kitty protocol vs legacy).
    pub(super) fn is_ctrl_shift_c(&self, key: &KeyEvent) -> bool {
        if !key.modifiers.contains(KeyModifiers::CONTROL) {
            return false;
        }
        match key.code {
            KeyCode::Char('C') => true,
            KeyCode::Char('c') => key.modifiers.contains(KeyModifiers::SHIFT),
            _ => false,
        }
    }
}

/// Build a [`FindSpec`] for a pending `f`/`F`/`t`/`T`. The target is a
/// placeholder until the next char key resolves it.
fn find_spec(till: bool, forward: bool) -> FindSpec {
    FindSpec {
        target: '\0',
        till,
        forward,
    }
}

fn is_modifier_only(key: &KeyEvent) -> bool {
    matches!(
        key.code,
        KeyCode::Modifier(_) | KeyCode::CapsLock | KeyCode::NumLock | KeyCode::ScrollLock
    )
}

/// `Ctrl+X` — force-close the embedded pane (GOALS §1i). Excludes Shift
/// so it's unambiguous under the kitty keyboard protocol.
fn is_pane_force_close(key: &KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::SHIFT)
        && matches!(key.code, KeyCode::Char('x') | KeyCode::Char('X'))
}

/// `Ctrl+K` — the which-key overlay leader (`which-key-overlay.md`). `Ctrl+X`
/// (the natural which-key chord) is already the embedded-pane force-close, so
/// the nearest free chord is used. Excludes Shift so it's unambiguous under the
/// kitty keyboard protocol; `Ctrl+K` is otherwise unbound in every mode.
fn is_keys_leader(key: &KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::SHIFT)
        && matches!(key.code, KeyCode::Char('k') | KeyCode::Char('K'))
}

/// `Ctrl+O` — toggle focus between the embedded pane and the composer.
fn is_pane_focus_toggle(key: &KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::SHIFT)
        && matches!(key.code, KeyCode::Char('o') | KeyCode::Char('O'))
}

fn is_ws_byte(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// Detect a *completed* `@`-tag whose right edge is exactly at `cursor`,
/// returning its `[start, cursor)` byte span. "Completed" means the tag
/// is terminated on the right (whitespace or end-of-buffer) and matches
/// one of: a quoted span `@"…"`, a tracked spaced path `@<accepted>`, or
/// a bare whitespace-free `@token`. Returns `None` when the cursor is
/// mid-tag or no completed tag ends here. This is what makes Backspace
/// at a tag's edge delete the whole tag atomically (GOALS §1e).
fn completed_tag_span(buffer: &str, cursor: usize, accepted: &[String]) -> Option<(usize, usize)> {
    if cursor == 0 {
        return None;
    }
    let bytes = buffer.as_bytes();
    let terminated = cursor >= buffer.len() || is_ws_byte(bytes[cursor]);
    if !terminated {
        return None;
    }

    // A — quoted: ends with a closing quote whose opener is `@"` at a
    // word boundary.
    if bytes[cursor - 1] == b'"'
        && let Some(qpos) = buffer[..cursor - 1].rfind('"')
        && qpos >= 1
        && bytes[qpos - 1] == b'@'
        && (qpos - 1 == 0 || is_ws_byte(bytes[qpos - 2]))
    {
        return Some((qpos - 1, cursor));
    }

    // B — tracked spaced path stored unquoted in the buffer: `@<accepted>`.
    // Longest first so a longer accepted path wins over a prefix.
    let mut tracked: Vec<&String> = accepted.iter().collect();
    tracked.sort_by_key(|p| std::cmp::Reverse(p.len()));
    for p in tracked {
        let need = p.len() + 1;
        if cursor >= need {
            let at = cursor - need;
            if bytes[at] == b'@'
                && &buffer[at + 1..cursor] == p.as_str()
                && (at == 0 || is_ws_byte(bytes[at - 1]))
            {
                return Some((at, cursor));
            }
        }
    }

    // C — bare whitespace-free `@token`.
    if let Some(at) = buffer[..cursor].rfind('@') {
        let seg = &buffer[at + 1..cursor];
        if at + 1 < cursor
            && !seg.chars().any(char::is_whitespace)
            && (at == 0 || is_ws_byte(bytes[at - 1]))
        {
            return Some((at, cursor));
        }
    }
    None
}

/// Mirror of [`completed_tag_span`] for forward-`Delete`: detect a tag
/// whose left edge (`@`) is exactly at `cursor`, returning `[cursor, end)`.
fn completed_tag_span_forward(
    buffer: &str,
    cursor: usize,
    accepted: &[String],
) -> Option<(usize, usize)> {
    let bytes = buffer.as_bytes();
    if cursor >= buffer.len() || bytes[cursor] != b'@' {
        return None;
    }
    if !(cursor == 0 || is_ws_byte(bytes[cursor - 1])) {
        return None;
    }
    let rest = &buffer[cursor + 1..];

    // A — quoted.
    if rest.starts_with('"') {
        if let Some(close_rel) = buffer[cursor + 2..].find('"') {
            let mut end = cursor + 2 + close_rel + 1;
            if buffer[end..].starts_with(':') {
                let rs = end + 1;
                let re = buffer[rs..]
                    .find(char::is_whitespace)
                    .map(|o| rs + o)
                    .unwrap_or(buffer.len());
                if re > rs
                    && buffer[rs..re]
                        .chars()
                        .all(|c| c.is_ascii_digit() || c == '-')
                {
                    end = re;
                }
            }
            return Some((cursor, end));
        }
        return None;
    }

    // B — tracked spaced path.
    let mut tracked: Vec<&String> = accepted.iter().collect();
    tracked.sort_by_key(|p| std::cmp::Reverse(p.len()));
    for p in tracked {
        if rest.starts_with(p.as_str()) {
            let end = cursor + 1 + p.len();
            if end >= buffer.len() || is_ws_byte(bytes[end]) {
                return Some((cursor, end));
            }
        }
    }

    // C — bare.
    let end = rest
        .find(char::is_whitespace)
        .map(|o| cursor + 1 + o)
        .unwrap_or(buffer.len());
    if end > cursor + 1 {
        Some((cursor, end))
    } else {
        None
    }
}

/// Render a toast over the status-line rect. Single line; left-padded
/// one cell; foreground color encodes intent (green/red/grey).
pub(super) fn accepts_key(key: &KeyEvent) -> bool {
    matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat)
}
/// True when `cursor` falls on the first line of `text` (i.e. there's
/// no `\n` in `text[..cursor]`). Used by history navigation to decide
/// "is the user at the top of the buffer?" — only then does Up step
/// into prompt history, otherwise it moves the cursor up one line.
fn cursor_on_first_line(text: &str, cursor: usize) -> bool {
    !text[..cursor.min(text.len())].contains('\n')
}

/// True when `cursor` falls on the last line of `text` (no `\n` after
/// it). Used by history navigation: Down only steps history when the
/// cursor is at the bottom of the buffer; otherwise it moves the
/// composer cursor down a line.
fn cursor_on_last_line(text: &str, cursor: usize) -> bool {
    let after = &text[cursor.min(text.len())..];
    !after.contains('\n')
}

fn validate_pasted_images_for_submit(images: &[Vec<u8>]) -> Result<(), String> {
    if images.is_empty() {
        return Ok(());
    }
    if images.len() > crate::daemon::proto::MAX_IMAGES_PER_USER_MESSAGE {
        return Err(format!(
            "Too many pasted images: {} exceeds the {} image limit.",
            images.len(),
            crate::daemon::proto::MAX_IMAGES_PER_USER_MESSAGE
        ));
    }
    let mut total = 0usize;
    for (idx, png) in images.iter().enumerate() {
        let display_idx = idx + 1;
        if png.is_empty() {
            return Err(format!("Pasted image #{display_idx} is empty."));
        }
        if png.len() > crate::daemon::proto::MAX_SINGLE_IMAGE_BYTES {
            return Err(format!(
                "Pasted image #{display_idx} is too large: {} bytes exceeds the {} byte limit.",
                png.len(),
                crate::daemon::proto::MAX_SINGLE_IMAGE_BYTES
            ));
        }
        total = total.saturating_add(png.len());
        if total > crate::daemon::proto::MAX_TOTAL_IMAGE_BYTES {
            return Err(format!(
                "Pasted images are too large: {} total bytes exceeds the {} byte limit.",
                total,
                crate::daemon::proto::MAX_TOTAL_IMAGE_BYTES
            ));
        }
        let image = image::load_from_memory_with_format(png, image::ImageFormat::Png)
            .map_err(|_| format!("Pasted image #{display_idx} is not a valid PNG."))?;
        if image.width() > crate::daemon::proto::MAX_IMAGE_DIMENSION_PIXELS
            || image.height() > crate::daemon::proto::MAX_IMAGE_DIMENSION_PIXELS
        {
            return Err(format!(
                "Pasted image #{display_idx} is too large: {}x{} exceeds the {} pixel dimension limit.",
                image.width(),
                image.height(),
                crate::daemon::proto::MAX_IMAGE_DIMENSION_PIXELS
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod image_submit_validation_tests {
    use super::validate_pasted_images_for_submit;

    fn sample_png() -> Vec<u8> {
        let image = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            1,
            1,
            image::Rgba([1, 2, 3, 255]),
        ));
        let mut out = Vec::new();
        image
            .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn accepts_valid_png_under_limits() {
        validate_pasted_images_for_submit(&[sample_png()]).unwrap();
    }

    #[test]
    fn rejects_too_many_images_before_dispatch() {
        let png = sample_png();
        let images = vec![png; crate::daemon::proto::MAX_IMAGES_PER_USER_MESSAGE + 1];
        let err = validate_pasted_images_for_submit(&images).expect_err("too many");
        assert!(err.contains("Too many pasted images"));
    }

    #[test]
    fn rejects_oversized_single_image_before_dispatch() {
        let images = vec![vec![0u8; crate::daemon::proto::MAX_SINGLE_IMAGE_BYTES + 1]];
        let err = validate_pasted_images_for_submit(&images).expect_err("oversized");
        assert!(err.contains("too large"));
        assert!(err.contains("byte limit"));
    }

    #[test]
    fn rejects_malformed_png_before_dispatch() {
        let images = vec![b"not png".to_vec()];
        let err = validate_pasted_images_for_submit(&images).expect_err("invalid png");
        assert!(err.contains("not a valid PNG"));
    }
}

#[cfg(test)]
mod tag_delete_tests {
    use super::{completed_tag_span, completed_tag_span_forward};

    fn none() -> Vec<String> {
        Vec::new()
    }

    #[test]
    fn bare_tag_at_eof_is_deletable() {
        // `@foo` with cursor at end (terminated by EOF).
        let b = "@foo";
        assert_eq!(completed_tag_span(b, b.len(), &none()), Some((0, 4)));
    }

    #[test]
    fn bare_tag_before_space_is_deletable() {
        // `@foo bar`, cursor right after `@foo` (index 4, space follows).
        assert_eq!(completed_tag_span("@foo bar", 4, &none()), Some((0, 4)));
    }

    #[test]
    fn cursor_mid_tag_is_not_deletable() {
        // cursor inside `@foo` (index 2) → normal char delete.
        assert_eq!(completed_tag_span("@foo", 2, &none()), None);
    }

    #[test]
    fn trailing_space_is_not_a_tag_edge() {
        // `@foo ` cursor after the space → first backspace removes space.
        assert_eq!(completed_tag_span("@foo ", 5, &none()), None);
    }

    #[test]
    fn quoted_tag_is_deletable_as_a_whole() {
        let b = "@\"my file.rs\"";
        assert_eq!(completed_tag_span(b, b.len(), &none()), Some((0, b.len())));
    }

    #[test]
    fn tracked_spaced_path_is_deletable() {
        let accepted = vec!["src/my file.rs".to_string()];
        let b = "@src/my file.rs";
        assert_eq!(
            completed_tag_span(b, b.len(), &accepted),
            Some((0, b.len()))
        );
    }

    #[test]
    fn email_at_is_not_a_tag() {
        // `user@host` — `@` not at a word boundary.
        assert_eq!(completed_tag_span("user@host", 9, &none()), None);
    }

    #[test]
    fn forward_delete_bare_tag() {
        // cursor at the `@` of `@foo bar`.
        assert_eq!(
            completed_tag_span_forward("@foo bar", 0, &none()),
            Some((0, 4))
        );
    }

    #[test]
    fn forward_delete_quoted_tag() {
        let b = "@\"my file.rs\" rest";
        assert_eq!(completed_tag_span_forward(b, 0, &none()), Some((0, 13)));
    }
}

#[cfg(test)]
mod queued_message_edit_tests {
    use super::{optimistic_queue_item, queue_item_from_proto};
    use crate::daemon::proto::{
        QueueItem, QueueItemStatus, RemoveQueuedUserMessageReason, Response,
    };
    use crate::engine::message::QueueItemStatus as EngineQueueItemStatus;
    use crate::tui::app::App;
    use crate::tui::history::HistoryEntry;

    fn proto_target(id: &str) -> crate::daemon::proto::QueueTarget {
        crate::daemon::proto::QueueTarget {
            id: id.to_string(),
            agent: "Build".to_string(),
            depth: 0,
            task_call_id: None,
        }
    }

    fn proto_item_with_target(
        text: &str,
        status: QueueItemStatus,
        target: crate::daemon::proto::QueueTarget,
    ) -> QueueItem {
        QueueItem {
            id: uuid::Uuid::new_v4(),
            status,
            text: text.to_string(),
            target,
        }
    }

    fn proto_item(text: &str, status: QueueItemStatus) -> QueueItem {
        proto_item_with_target(text, status, crate::daemon::proto::QueueTarget::default())
    }

    #[test]
    fn up_edit_success_removes_daemon_items_fifo_and_fills_composer() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.queue.push(optimistic_queue_item("older".to_string()));
        app.queue.push(optimistic_queue_item("edit me".to_string()));
        let older = app.queue[0].clone();
        let newer = app.queue[1].clone();
        app.queued_tag_batches.push(Vec::new());
        app.queued_tag_batches
            .push(vec![crate::tui::file_tag::TagExpansion {
                tool: "read",
                path: "a.rs".to_string(),
                ok: true,
                detail: "1 line".to_string(),
            }]);

        app.edit_queued_messages_for_test(Response::RemoveQueuedUserMessagesResult {
            applied: true,
            reason: RemoveQueuedUserMessageReason::Removed,
            removed_items: vec![
                QueueItem {
                    id: older.id,
                    status: QueueItemStatus::Queued,
                    text: older.text,
                    target: crate::daemon::proto::QueueTarget::default(),
                },
                QueueItem {
                    id: newer.id,
                    status: QueueItemStatus::Queued,
                    text: newer.text,
                    target: crate::daemon::proto::QueueTarget::default(),
                },
            ],
            queue: Vec::new(),
        });

        assert_eq!(app.composer.text(), "older\n\nedit me");
        assert!(app.queue.is_empty());
        assert!(
            app.queued_tag_batches.is_empty(),
            "tag metadata for removed queued messages is dropped"
        );
        assert_eq!(app.prompt_history_cursor, 0);
    }

    #[test]
    fn up_edit_already_started_leaves_composer_and_shows_notice() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.queue.push(optimistic_queue_item("started".to_string()));

        app.edit_queued_messages_for_test(Response::RemoveQueuedUserMessagesResult {
            applied: false,
            reason: RemoveQueuedUserMessageReason::AlreadyStarted,
            removed_items: Vec::new(),
            queue: vec![proto_item("started", QueueItemStatus::Folding)],
        });

        assert!(app.composer.is_empty());
        assert_eq!(app.queue[0].status, EngineQueueItemStatus::Folding);
        assert!(
            matches!(&app.toast, Some(toast) if toast.text == "queued message already started"),
            "already-started removal failure is visible"
        );
    }

    #[test]
    fn up_edit_uses_daemon_removed_item_when_local_mirror_is_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.queue
            .push(optimistic_queue_item("local stale".to_string()));
        app.queued_tag_batches
            .push(vec![crate::tui::file_tag::TagExpansion {
                tool: "read",
                path: "stale.rs".to_string(),
                ok: true,
                detail: "1 line".to_string(),
            }]);

        app.edit_queued_messages_for_test(Response::RemoveQueuedUserMessagesResult {
            applied: true,
            reason: RemoveQueuedUserMessageReason::Removed,
            removed_items: vec![proto_item("daemon authoritative", QueueItemStatus::Queued)],
            queue: Vec::new(),
        });

        assert_eq!(app.composer.text(), "daemon authoritative");
        assert!(app.queue.is_empty());
        assert!(
            app.queued_tag_batches.is_empty(),
            "stale local tag metadata is discarded with the stale queue row"
        );
    }

    #[test]
    fn up_edit_partial_started_keeps_removed_draft_and_shows_notice() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.queue
            .push(optimistic_queue_item("editable".to_string()));
        let editable = app.queue[0].clone();

        app.edit_queued_messages_for_test(Response::RemoveQueuedUserMessagesResult {
            applied: true,
            reason: RemoveQueuedUserMessageReason::AlreadyStarted,
            removed_items: vec![QueueItem {
                id: editable.id,
                status: QueueItemStatus::Queued,
                text: editable.text,
                target: crate::daemon::proto::QueueTarget::default(),
            }],
            queue: Vec::new(),
        });

        assert_eq!(app.composer.text(), "editable");
        assert!(app.queue.is_empty());
        assert!(
            matches!(&app.toast, Some(toast) if toast.text == "some queued messages already started"),
            "partial edit outcome is visible"
        );
    }

    #[test]
    fn up_edit_not_found_keeps_other_target_queue_and_shows_toast_only() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let other = proto_item_with_target(
            "other target",
            QueueItemStatus::Queued,
            proto_target("task:1:child"),
        );
        app.queue.push(queue_item_from_proto(other.clone()));

        app.edit_queued_messages_for_test(Response::RemoveQueuedUserMessagesResult {
            applied: false,
            reason: RemoveQueuedUserMessageReason::NotFound,
            removed_items: Vec::new(),
            queue: vec![other],
        });

        assert!(app.composer.is_empty());
        assert_eq!(app.queue[0].text, "other target");
        assert!(
            matches!(&app.toast, Some(toast) if toast.text == "queued messages could not be edited"),
            "target-miss removal failure is visible"
        );
        assert!(
            !app.history
                .iter()
                .any(|entry| matches!(entry, HistoryEntry::Plain { .. })),
            "queue-edit failures use a toast instead of transcript noise"
        );
    }

    #[test]
    fn edit_response_for_folding_queue_item_shows_already_started_notice() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.queue.push(queue_item_from_proto(proto_item(
            "started",
            QueueItemStatus::Folding,
        )));

        app.edit_queued_messages_for_test(Response::RemoveQueuedUserMessagesResult {
            applied: false,
            reason: RemoveQueuedUserMessageReason::AlreadyStarted,
            removed_items: Vec::new(),
            queue: vec![proto_item("started", QueueItemStatus::Folding)],
        });

        assert!(app.composer.is_empty());
        assert!(
            matches!(&app.toast, Some(toast) if toast.text == "queued message already started"),
            "folding queued items are no longer editable via Up"
        );
    }

    #[test]
    fn queue_updated_event_drives_visible_queue() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.queue
            .push(optimistic_queue_item("local stale".to_string()));
        let daemon_item = proto_item("daemon item", QueueItemStatus::Queued);

        app.apply_event(crate::engine::TurnEvent::QueueUpdated {
            queue: vec![queue_item_from_proto(daemon_item)],
        });

        assert_eq!(
            app.queue
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["daemon item"]
        );
    }

    #[test]
    fn history_up_after_queue_edit_saves_and_restores_folded_draft() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.composer.set("first\n\nsecond".to_string());
        app.composer.set_cursor(0);
        app.prompt_history.push("previous prompt".to_string());

        app.history_up();

        assert_eq!(app.composer.text(), "previous prompt");
        assert_eq!(app.prompt_history_cursor, 1);

        app.history_down();

        assert_eq!(app.composer.text(), "first\n\nsecond");
        assert_eq!(app.prompt_history_cursor, 0);
    }

    #[test]
    fn history_up_uses_prompt_history_when_no_queue_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.prompt_history.push("previous prompt".to_string());

        app.history_up();

        assert_eq!(app.composer.text(), "previous prompt");
        assert_eq!(app.prompt_history_cursor, 1);
    }
}

#[cfg(test)]
mod paste_routing_tests {
    use crate::db::pins::PinnedMessage;
    use crate::tui::app::App;
    use crate::tui::keys_overlay::{KeyContext, KeysOverlay};
    use crate::tui::pins_overlay::{CopyPick, ForkPick, PinPick, PinsReview};
    use crate::tui::settings::Dialog;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn input_ready_app(tmp: &tempfile::TempDir) -> App {
        let mut app = App::new(Some(tmp.path()), false);
        app.daemon_prompt = None;
        app.dialog = Dialog::None;
        app
    }

    fn ctrl(ch: char) -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char(ch),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn assert_modal_paste_is_dropped<F>(setup: F)
    where
        F: FnOnce(&mut App),
    {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = input_ready_app(&tmp);
        setup(&mut app);

        app.handle_paste("modal paste".to_string());

        assert!(app.composer.is_empty());
        assert!(app.paste_registry.is_empty());
    }

    #[test]
    fn paste_is_dropped_while_non_text_modals_are_open() {
        assert_modal_paste_is_dropped(|app| {
            app.pin_pick = PinPick::enter(vec![0]);
        });
        assert_modal_paste_is_dropped(|app| {
            app.fork_pick = ForkPick::enter(vec![0]);
        });
        assert_modal_paste_is_dropped(|app| {
            app.copy_pick = CopyPick::enter(vec![0]);
        });
        assert_modal_paste_is_dropped(|app| {
            app.pins_review = PinsReview::enter(vec![PinnedMessage {
                seq: 1,
                is_assistant: false,
                text: "pinned".to_string(),
            }]);
        });
        assert_modal_paste_is_dropped(|app| {
            app.keys_overlay = Some(KeysOverlay::open(KeyContext::Composer));
        });
        assert_modal_paste_is_dropped(|app| {
            app.handle_key(ctrl('f'));
            assert!(app.transcript_find.is_some());
        });
    }

    #[test]
    fn paste_routes_to_open_notes_pane() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = input_ready_app(&tmp);
        app.notes_pane = Some(crate::tui::notes_pane::NotesPane::editing_for_test(
            "", false,
        ));

        app.handle_paste("hi".to_string());

        let pane = app.notes_pane.as_ref().expect("notes pane stays open");
        assert_eq!(pane.editor_text_for_test(), "hi");
        assert!(app.composer.is_empty());
        assert!(app.paste_registry.is_empty());
    }

    #[cfg(unix)]
    fn spawn_cat_pane(app: &mut App, focused: bool) {
        let argv = vec!["cat".to_string()];
        let cwd = std::env::temp_dir();
        let pane =
            crate::tui::pty::PtyPane::spawn(crate::tui::pty::PaneKind::Editor, &argv, &cwd, 24, 80)
                .expect("spawn cat pty child");
        app.pane = Some(pane);
        app.pane_focused = focused;
    }

    #[cfg(unix)]
    fn wait_for_pane_text(app: &App, needle: &str) -> bool {
        for _ in 0..50 {
            let contains = app
                .pane
                .as_ref()
                .map(|pane| pane.screen_contents_for_test().contains(needle))
                .unwrap_or(false);
            if contains {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        false
    }

    #[cfg(unix)]
    #[test]
    fn paste_routes_to_focused_pty_pane() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = input_ready_app(&tmp);
        spawn_cat_pane(&mut app, true);

        app.handle_paste("hello\n".to_string());

        assert!(wait_for_pane_text(&app, "hello"));
        assert!(app.composer.is_empty());
        assert!(app.paste_registry.is_empty());
        app.close_pane(true);
    }

    #[cfg(unix)]
    #[test]
    fn paste_shortcut_chars_reach_focused_pty_pane() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = input_ready_app(&tmp);
        spawn_cat_pane(&mut app, true);

        app.handle_paste("cqjk\n".to_string());

        assert!(wait_for_pane_text(&app, "cqjk"));
        assert!(app.composer.is_empty());
        app.close_pane(true);
    }

    #[cfg(unix)]
    #[test]
    fn paste_ignores_unfocused_pty_pane() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = input_ready_app(&tmp);
        spawn_cat_pane(&mut app, false);

        app.handle_paste("hello".to_string());

        assert_eq!(app.composer.text(), "hello");
        assert!(
            !app.pane
                .as_ref()
                .expect("pane remains open")
                .screen_contents_for_test()
                .contains("hello")
        );
        app.close_pane(true);
    }
}

#[cfg(test)]
mod slash_cursor_tests {
    use super::super::App;
    use crate::tui::nav::{wrap_next, wrap_prev};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    /// The slash-menu cursor mirrors the `@`-popup: the highlight moves
    /// with the same wrap math the handler applies, and the default
    /// highlight is index 0 — the frequency-ranked top match (see
    /// `slash_rank_tests`), preserving "type `/foo` + Enter runs the top
    /// match" muscle memory.
    #[test]
    fn cursor_default_is_top_match_and_wraps() {
        // A fresh slash session starts on the top-ranked match.
        let mut sel = 0usize;
        let n = 3usize; // e.g. /settings, /session, /stats
        assert_eq!(sel, 0, "default highlight is the top match");
        // Up from the top wraps to the last.
        sel = wrap_prev(sel, n);
        assert_eq!(sel, 2);
        // Down from the last wraps back to the top.
        sel = wrap_next(sel, n);
        assert_eq!(sel, 0);
        // Interior Down steps normally.
        sel = wrap_next(sel, n);
        assert_eq!(sel, 1);
    }

    /// Recall suppression is scoped to "menu visible": the handler routes
    /// Up/Down to slash-nav exactly when `slash_query().is_some()`, and to
    /// composer history recall otherwise. This models that branch.
    #[test]
    fn history_recall_suppressed_only_while_menu_visible() {
        fn up_does_slash_nav(slash_query_is_some: bool) -> bool {
            // The handler's gate: while a slash query is active, Up/Down
            // move the menu cursor and return early; otherwise they fall
            // through to `history_up`/`history_down`.
            slash_query_is_some
        }
        assert!(up_does_slash_nav(true), "menu visible → slash nav");
        assert!(
            !up_does_slash_nav(false),
            "menu not visible → history recall resumes"
        );
    }

    /// A single-item match set (the common `/foo` exact-prefix case)
    /// stays on its one item under either arrow.
    #[test]
    fn single_match_stays_put() {
        assert_eq!(wrap_next(0, 1), 0);
        assert_eq!(wrap_prev(0, 1), 0);
    }

    fn slash_app() -> App {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.composer.set("/".to_string());
        app.reset_slash_window();
        app
    }

    #[test]
    fn down_navigation_reaches_beyond_visible_slash_window() {
        let mut app = slash_app();
        let n = app.slash_suggestions().len();
        assert!(n > super::super::AUTOCOMPLETE_ROWS as usize);

        for _ in 0..super::super::AUTOCOMPLETE_ROWS {
            app.handle_key_insert(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        }

        assert_eq!(app.slash_selected, super::super::AUTOCOMPLETE_ROWS as usize);
        assert!(
            app.slash_scroll > 0,
            "selection beyond the first window should scroll the slash menu"
        );
    }

    #[test]
    fn up_navigation_moves_back_across_scrolled_slash_window() {
        let mut app = slash_app();
        for _ in 0..super::super::AUTOCOMPLETE_ROWS {
            app.handle_key_insert(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        }
        assert!(app.slash_scroll > 0);

        app.handle_key_insert(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));

        assert_eq!(
            app.slash_selected,
            super::super::AUTOCOMPLETE_ROWS as usize - 1
        );
    }

    #[test]
    fn tab_completion_can_choose_beyond_visible_slash_window() {
        let mut app = slash_app();
        let expected =
            app.slash_suggestions()[super::super::AUTOCOMPLETE_ROWS as usize].completion_text();
        for _ in 0..super::super::AUTOCOMPLETE_ROWS {
            app.handle_key_insert(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        }

        assert!(app.complete_slash_selection());

        assert_eq!(app.composer.text(), expected);
    }

    #[test]
    fn query_shrink_resets_slash_selection_and_scroll() {
        let mut app = slash_app();
        for _ in 0..super::super::AUTOCOMPLETE_ROWS {
            app.handle_key_insert(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        }
        assert!(app.slash_selected > 0);
        assert!(app.slash_scroll > 0);

        app.composer.set("/zzzz-no-match".to_string());
        app.reset_slash_window();

        assert_eq!(app.slash_suggestions().len(), 0);
        assert_eq!(app.slash_selected, 0);
        assert_eq!(app.slash_scroll, 0);
    }

    /// Pure model of `App::complete_slash_selection`
    /// (`slash-command-tab-completion.md`): given the candidate
    /// completions (`/name` or `/name ` per the command's arg-marker), the
    /// current highlight, and the composer text, return the new composer
    /// text + highlight after one Tab. A repeat Tab — composer already
    /// equals the highlighted completion — advances to the next match
    /// before completing, so Tab cycles forward like ↓.
    fn tab_complete(
        completions: &[&str],
        selected: usize,
        composer: &str,
    ) -> Option<(String, usize)> {
        if completions.is_empty() {
            // Menu open but zero matches → Tab is a no-op.
            return None;
        }
        let n = completions.len();
        let mut idx = selected.min(n - 1);
        if composer == completions[idx] {
            idx = wrap_next(idx, n);
        }
        Some((completions[idx].to_string(), idx))
    }

    #[test]
    fn first_tab_completes_to_highlighted_without_submitting() {
        // `/se` → menu highlight on the top match `/settings`; Tab fills
        // the composer with the full name. No trailing space (bare cmd).
        let comps = ["/settings", "/session", "/stats"];
        let (text, sel) = tab_complete(&comps, 0, "/se").unwrap();
        assert_eq!(text, "/settings", "completes to the highlighted command");
        assert_eq!(sel, 0, "first Tab keeps the highlight on the top match");
    }

    #[test]
    fn arg_command_completion_carries_a_trailing_space() {
        // An arg-taking command's completion ends in a space so the
        // cursor lands ready for the argument; a bare one does not.
        let with_args = ["/copy "];
        let (text, _) = tab_complete(&with_args, 0, "/co").unwrap();
        assert_eq!(text, "/copy ");
        let bare = ["/settings"];
        let (text, _) = tab_complete(&bare, 0, "/se").unwrap();
        assert_eq!(text, "/settings");
    }

    #[test]
    fn second_tab_advances_to_next_match_and_completes() {
        // After the first Tab landed `/settings`, a second Tab (composer
        // already equals the highlighted completion) advances to the next
        // anchored match and completes to it.
        let comps = ["/settings", "/session", "/stats"];
        let (text, sel) = tab_complete(&comps, 0, "/settings").unwrap();
        assert_eq!(text, "/session", "second Tab cycles to the next match");
        assert_eq!(sel, 1);
        // A third Tab advances again, and the last wraps back to the top.
        let (text, sel) = tab_complete(&comps, sel, "/session").unwrap();
        assert_eq!(text, "/stats");
        assert_eq!(sel, 2);
        let (text, sel) = tab_complete(&comps, sel, "/stats").unwrap();
        assert_eq!(text, "/settings", "Tab wraps forward like ↓");
        assert_eq!(sel, 0);
    }

    #[test]
    fn tab_with_zero_matches_is_a_no_op() {
        // Menu open (composer starts with `/`) but nothing matches: the
        // helper makes no change and reports no completion.
        assert!(tab_complete(&[], 0, "/zzzz").is_none());
    }

    /// Guard: the new slash-Tab branch is gated on the slash menu being
    /// open (`slash_query().is_some()`), which is mutually exclusive with
    /// the `@`-popup (needs an `@`-token) and the prediction-ghost path
    /// (needs an *empty* composer). This models those gates so the three
    /// Tab contexts stay cleanly separated.
    #[test]
    fn tab_branches_are_mutually_exclusive() {
        // (slash_open, composer_empty, at_token_present)
        fn slash_tab_fires(slash_open: bool) -> bool {
            slash_open
        }
        fn prediction_tab_fires(composer_empty: bool, has_ghost: bool, slash_open: bool) -> bool {
            // The prediction-ghost arm is reached only when the composer
            // is empty (so no slash query can exist) with a pending ghost.
            composer_empty && has_ghost && !slash_open
        }
        // Slash menu open: only the slash branch fires.
        assert!(slash_tab_fires(true));
        assert!(!prediction_tab_fires(false, true, true));
        // Empty composer with a ghost: only the prediction branch fires;
        // an empty composer can't start with `/`, so no slash query.
        assert!(!slash_tab_fires(false));
        assert!(prediction_tab_fires(true, true, false));
    }
}

#[cfg(test)]
mod chat_scrollback_key_tests {
    use super::super::Selection;
    use super::*;
    use crate::tui::keys_overlay::{KeyContext, KeysOverlay};
    use crossterm::event::{KeyEventState, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn shifted(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::SHIFT,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn ctrl(ch: char) -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char(ch),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn char_key(ch: char) -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char(ch),
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn scrollable_app() -> App {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.daemon_prompt = None;
        app.dialog = Dialog::None;
        app.chat_total_lines = 20;
        app.chat_visible_lines = 6;
        app
    }

    #[test]
    fn page_keys_scroll_chat_by_visible_page_with_overlap() {
        let mut app = scrollable_app();

        app.handle_key(press(KeyCode::PageUp));
        assert_eq!(app.chat_scroll_offset, 5);

        app.handle_key(press(KeyCode::PageDown));
        assert_eq!(app.chat_scroll_offset, 0);
    }

    #[test]
    fn shifted_arrows_scroll_chat_by_one_line() {
        let mut app = scrollable_app();

        app.handle_key(shifted(KeyCode::Up));
        assert_eq!(app.chat_scroll_offset, 1);

        app.handle_key(shifted(KeyCode::Down));
        assert_eq!(app.chat_scroll_offset, 0);
    }

    #[test]
    fn end_jumps_to_live_tail_only_when_composer_empty() {
        let mut app = scrollable_app();
        app.chat_scroll_offset = 7;

        app.handle_key(press(KeyCode::End));
        assert_eq!(app.chat_scroll_offset, 0);

        app.chat_scroll_offset = 7;
        app.composer.set("draft".to_string());
        app.composer.set_cursor(0);
        app.handle_key(press(KeyCode::End));
        assert_eq!(app.chat_scroll_offset, 7);
        assert_eq!(app.composer.cursor(), app.composer.text().len());
    }

    #[test]
    fn page_up_is_mode_agnostic() {
        let mut insert = scrollable_app();
        insert.composer.set_vim_enabled(true);
        insert.composer.set_vim_mode(VimMode::Insert);
        insert.handle_key(press(KeyCode::PageUp));
        assert_eq!(insert.chat_scroll_offset, 5);

        let mut normal = scrollable_app();
        normal.composer.set_vim_enabled(true);
        normal.composer.set_vim_mode(VimMode::Normal);
        normal.handle_key(press(KeyCode::PageUp));
        assert_eq!(normal.chat_scroll_offset, 5);

        let mut disabled = scrollable_app();
        disabled.composer.set_vim_enabled(false);
        disabled.handle_key(press(KeyCode::PageUp));
        assert_eq!(disabled.chat_scroll_offset, 5);
    }

    #[test]
    fn page_up_does_not_leak_through_keys_overlay() {
        let mut app = scrollable_app();
        app.keys_overlay = Some(KeysOverlay::open(KeyContext::Composer));

        app.handle_key(press(KeyCode::PageUp));

        assert_eq!(app.chat_scroll_offset, 0);
    }

    #[test]
    fn keyboard_scrollback_clears_selection() {
        let mut app = scrollable_app();
        app.selection = Some(Selection {
            anchor: (0, 0),
            focus: (1, 1),
            active: false,
        });

        app.handle_key(press(KeyCode::PageUp));

        assert!(app.selection.is_none());
        assert_eq!(app.chat_scroll_offset, 5);
    }

    #[test]
    fn ctrl_f_opens_transcript_find_without_inserting_composer_text() {
        let mut app = scrollable_app();

        app.handle_key(ctrl('f'));

        assert!(app.transcript_find.is_some());
        assert_eq!(app.composer.text(), "");
    }

    #[test]
    fn transcript_find_matches_case_insensitive_and_cycles_without_bare_n_binding() {
        let mut app = scrollable_app();
        app.chat_find_lines = vec![
            "alpha".to_string(),
            "Needle one".to_string(),
            "middle".to_string(),
            "needle two".to_string(),
        ];
        app.chat_total_lines = app.chat_find_lines.len();
        app.chat_visible_lines = 2;

        app.handle_key(ctrl('f'));
        for ch in "NEEDLE".chars() {
            app.handle_key(char_key(ch));
        }
        assert_eq!(app.transcript_find.as_ref().unwrap().matches, vec![1, 3]);
        assert_eq!(app.transcript_find.as_ref().unwrap().current, Some(0));

        app.handle_key(press(KeyCode::Down));
        assert_eq!(app.transcript_find.as_ref().unwrap().current, Some(1));
        app.handle_key(char_key('n'));
        assert_eq!(app.transcript_find.as_ref().unwrap().query, "NEEDLEn");
        assert!(app.transcript_find.as_ref().unwrap().matches.is_empty());
    }

    #[test]
    fn transcript_find_escape_restores_offset_and_enter_keeps_match_offset() {
        let mut app = scrollable_app();
        app.chat_find_lines = vec![
            "old target".to_string(),
            "middle".to_string(),
            "bottom".to_string(),
        ];
        app.chat_total_lines = app.chat_find_lines.len();
        app.chat_visible_lines = 1;
        app.chat_scroll_offset = 0;

        app.handle_key(ctrl('f'));
        for ch in "old".chars() {
            app.handle_key(char_key(ch));
        }
        assert_ne!(app.chat_scroll_offset, 0);
        app.handle_key(press(KeyCode::Esc));
        assert!(app.transcript_find.is_none());
        assert_eq!(app.chat_scroll_offset, 0);

        app.handle_key(ctrl('f'));
        for ch in "old".chars() {
            app.handle_key(char_key(ch));
        }
        let matched_offset = app.chat_scroll_offset;
        app.handle_key(press(KeyCode::Enter));
        assert!(app.transcript_find.is_none());
        assert_eq!(app.chat_scroll_offset, matched_offset);
    }
}

#[cfg(test)]
mod dispatch_span_tests {
    use super::super::DispatchOutcome;

    /// Reproduce `submit_input`'s working-span teardown rule without a
    /// live daemon. The bug was that a failed-start submit left `busy`
    /// stuck `true` forever, since `AgentIdle` (the sole falling edge)
    /// never arrives when no worker was spawned. This models the exact
    /// production gate (`owns_working_span && outcome.span_orphaned()`)
    /// against the `begin`/`end_working_span` semantics (`busy` true on
    /// rising edge, false on falling edge).
    fn busy_after_fresh_submit(outcome: DispatchOutcome) -> bool {
        // Fresh-submit path always owns the rising edge it just opened.
        let owns_working_span = true;
        let mut busy = true; // begin_working_span() set this.
        if owns_working_span && outcome.span_orphaned() {
            busy = false; // end_working_span() lowers it.
        }
        busy
    }

    #[test]
    fn runner_failed_clears_busy() {
        // The reported stuck-span case: runner is `Some(Err(_))`.
        assert!(!busy_after_fresh_submit(DispatchOutcome::RunnerFailed));
    }

    #[test]
    fn queue_full_and_driver_closed_clear_busy() {
        assert!(!busy_after_fresh_submit(DispatchOutcome::QueueFull));
        assert!(!busy_after_fresh_submit(DispatchOutcome::DriverClosed));
    }

    #[test]
    fn successful_send_keeps_busy_until_agent_idle() {
        // A normal turn stays "working"; only `AgentIdle` ends it.
        assert!(busy_after_fresh_submit(DispatchOutcome::Sent));
    }

    #[test]
    fn queue_path_never_tears_down_a_span() {
        // The busy/queue path started no span this submit, so even an
        // orphaning outcome must leave any in-flight turn's span alone.
        let owns_working_span = false;
        let mut busy = true; // a legitimately in-flight turn.
        if owns_working_span && DispatchOutcome::RunnerFailed.span_orphaned() {
            busy = false;
        }
        assert!(busy);
    }
}
