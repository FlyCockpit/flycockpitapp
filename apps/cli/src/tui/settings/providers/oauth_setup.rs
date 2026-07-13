use super::*;

pub(super) fn render_copilot_body(lines: &mut Vec<Line<'static>>, s: &CopilotSetupState) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let red = Style::default().fg(Color::Red);
    let green = Style::default().fg(Color::Green);
    let cyan = Style::default().fg(Color::Cyan);

    if let Some(outcome) = &s.outcome {
        // Post-action result screen.
        match outcome {
            Ok(msg) => {
                lines.push(Line::from(Span::styled(msg.clone(), green)));
            }
            Err(e) => {
                lines.push(Line::from(Span::styled(format!("Failed: {e}"), red)));
            }
        }
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Press Enter to continue.".to_string(),
            muted,
        )));
        return;
    }

    match (s.shell, &s.rc_path, s.already_configured) {
        (Some(shell), Some(rc_path), false) => {
            lines.push(Line::from(Span::styled(
                format!("Detected shell: {}", shell.name()),
                muted,
            )));
            lines.push(Line::from(vec![
                Span::styled("Will append to: ".to_string(), muted),
                Span::styled(rc_path.display().to_string(), cyan),
            ]));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Lines to be added:".to_string(),
                muted,
            )));
            for line in copilot_setup::append_block(shell).lines() {
                if line.is_empty() {
                    lines.push(Line::default());
                } else {
                    lines.push(Line::from(Span::styled(format!("    {line}"), cyan)));
                }
            }
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "We'll also run `gh auth token` once and set GH_TOKEN in this \
                     cockpit session so Copilot works without restarting."
                    .to_string(),
                muted,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Press Enter to apply, Esc to cancel.".to_string(),
                yellow,
            )));
        }
        (Some(shell), Some(rc_path), true) => {
            lines.push(Line::from(Span::styled(
                format!(
                    "{} already contains the cockpit Copilot-auth export.",
                    rc_path.display()
                ),
                muted,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                format!(
                    "To re-apply: remove the marker block from your {} and try again.",
                    shell.rc_filename()
                ),
                muted,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Press Enter or Esc to return.".to_string(),
                yellow,
            )));
        }
        _ => {
            // Unsupported shell or unknown $HOME — show manual
            // instructions instead of a write button.
            lines.push(Line::from(Span::styled(
                "Couldn't detect a supported shell ($SHELL is unset, or it's \
                     not zsh/bash/fish). Set GH_TOKEN manually with one of:"
                    .to_string(),
                muted,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "  POSIX shell (zsh/bash/sh):".to_string(),
                muted,
            )));
            lines.push(Line::from(Span::styled(
                "    export GH_TOKEN=$(gh auth token)".to_string(),
                cyan,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled("  fish:".to_string(), muted)));
            lines.push(Line::from(Span::styled(
                "    set -Ux GH_TOKEN (gh auth token)".to_string(),
                cyan,
            )));
            if cfg!(windows) {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "  Windows PowerShell ($PROFILE):".to_string(),
                    muted,
                )));
                lines.push(Line::from(Span::styled(
                    "    $env:GH_TOKEN = (gh auth token)".to_string(),
                    cyan,
                )));
                lines.push(Line::from(Span::styled(
                    "  Windows persistent (User scope):".to_string(),
                    muted,
                )));
                lines.push(Line::from(Span::styled(
                    "    [Environment]::SetEnvironmentVariable(\"GH_TOKEN\", \
                         (gh auth token), \"User\")"
                        .to_string(),
                    cyan,
                )));
            }
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Press Enter or Esc to return.".to_string(),
                yellow,
            )));
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum OAuthFlowView<'a> {
    Copilot(&'a CopilotSetupState),
    Grok(&'a BrowserCallbackOAuthState),
    Codex(&'a DeviceCodeOAuthState),
}

impl OAuthFlowView<'_> {
    pub(super) fn confirming(self) -> bool {
        match self {
            OAuthFlowView::Copilot(_) => false,
            OAuthFlowView::Grok(s) => {
                oauth_setup_confirming_logged_in(s.logged_in, s.pending, s.paste_focused)
            }
            OAuthFlowView::Codex(s) => {
                oauth_setup_confirming_logged_in(s.logged_in, s.polling, false)
            }
        }
    }

    pub(super) fn option_count(self) -> usize {
        if self.confirming() {
            return 1;
        }
        match self {
            OAuthFlowView::Copilot(_) => 1,
            OAuthFlowView::Grok(_) => 3,
            OAuthFlowView::Codex(_) => 2,
        }
    }
}

pub(super) fn oauth_setup_lines(flow: OAuthFlowView<'_>) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let title = match flow {
        OAuthFlowView::Copilot(_) => "Set up GitHub Copilot auth",
        OAuthFlowView::Grok(_) => "Set up Grok subscription auth",
        OAuthFlowView::Codex(_) => "Set up Codex subscription auth",
    };
    lines.push(Line::from(Span::styled(
        title.to_string(),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::default());
    render_oauth_body(&mut lines, flow);
    lines
}

pub(super) fn render_oauth_setup(
    frame: &mut Frame,
    area: Rect,
    flow: OAuthFlowView<'_>,
    links: Option<&mut crate::tui::links::LinkRegistry>,
) {
    let mut lines = oauth_setup_lines(flow);
    let link_regions = super::prepare_oauth_link_regions(&mut lines, area, flow, links.as_deref())
        .unwrap_or_default();
    frame.render_widget(Paragraph::new(lines), area);
    if let Some(links) = links {
        super::register_visible_link_regions(links, area, 0, link_regions);
    }
}

pub(super) fn render_oauth_body(lines: &mut Vec<Line<'static>>, flow: OAuthFlowView<'_>) {
    match flow {
        OAuthFlowView::Copilot(s) => render_copilot_body(lines, s),
        OAuthFlowView::Grok(s) => render_grok_oauth_body(lines, s),
        OAuthFlowView::Codex(s) => render_codex_oauth_body(lines, s),
    }
}

pub(super) fn handle_browser_callback_oauth_key(
    key: KeyEvent,
    s: &mut BrowserCallbackOAuthState,
) -> (bool, Option<OAuthActionRequest>) {
    if s.paste_focused {
        match key.code {
            KeyCode::Esc => {
                s.paste_focused = false;
                return (false, None);
            }
            KeyCode::Enter => {
                let Some(login) = s.manual_login.clone() else {
                    s.status = Some(Err("manual OAuth session was not initialized".into()));
                    s.paste_focused = false;
                    return (false, None);
                };
                let input = s.manual_input.text().to_string();
                if input.trim().is_empty() {
                    s.status = Some(Err("paste callback URL or code first".to_string()));
                    return (false, None);
                }
                s.pending = true;
                s.status = Some(Ok("Completing xAI OAuth login...".to_string()));
                return (
                    false,
                    Some(OAuthActionRequest::GrokComplete { login, input }),
                );
            }
            _ => {
                s.manual_input.handle_key(key);
                return (false, None);
            }
        }
    }

    if s.pending && matches!(key.code, KeyCode::Esc) {
        s.pending = false;
        s.status = Some(Ok("OAuth login cancelled".to_string()));
        return (false, Some(OAuthActionRequest::GrokCancel));
    }

    if matches!(key.code, KeyCode::Char('c')) {
        copy_oauth_url_with(
            s.authorize_url.as_deref(),
            &mut s.status,
            crate::clipboard::copy_plain,
        );
        return (false, None);
    }

    match key.code {
        KeyCode::Esc => (true, Some(OAuthActionRequest::GrokCancel)),
        KeyCode::Up | KeyCode::Char('k') => {
            let len = OAuthFlowView::Grok(s).option_count();
            s.cursor = oauth_option_cursor_prev(s.cursor, len);
            (false, None)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let len = OAuthFlowView::Grok(s).option_count();
            s.cursor = oauth_option_cursor_next(s.cursor, len);
            (false, None)
        }
        KeyCode::Enter => {
            if OAuthFlowView::Grok(s).confirming() {
                s.cursor = 0;
                return (false, None);
            }
            if s.pending {
                if s.cursor == 0 {
                    s.paste_focused = true;
                    s.manual_input.set("");
                }
                return (false, None);
            }
            if s.cursor == 0 || s.cursor == 1 {
                let selection = if s.cursor == 1 {
                    GrokLoginSelection::ManualOnly
                } else {
                    grok_login_selection(s.ssh_manual_only)
                };
                s.pending = true;
                s.paste_focused = false;
                s.manual_input.set("");
                s.status = Some(Ok(if s.cursor == 0 && !s.ssh_manual_only {
                    "Preparing xAI OAuth login...".to_string()
                } else if s.ssh_manual_only {
                    "SSH detected; browser auto-open is unavailable here".to_string()
                } else {
                    "Preparing manual xAI OAuth login...".to_string()
                }));
                return (
                    false,
                    Some(OAuthActionRequest::GrokBegin {
                        is_ssh: matches!(selection, GrokLoginSelection::ManualOnly),
                    }),
                );
            }
            (false, None)
        }
        _ => (false, None),
    }
}

fn render_grok_oauth_body(lines: &mut Vec<Line<'static>>, s: &BrowserCallbackOAuthState) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let green = Style::default().fg(Color::Green);
    let red = Style::default().fg(Color::Red);
    let cyan = Style::default().fg(Color::Cyan);

    lines.push(Line::from(vec![
        Span::styled("Status: ", muted),
        Span::styled(
            if s.logged_in {
                "logged in"
            } else {
                "not logged in"
            }
            .to_string(),
            if s.logged_in { green } else { red },
        ),
    ]));
    lines.push(Line::from(Span::styled(
        "Uses your SuperGrok subscription quota via xAI's sanctioned OAuth flow.".to_string(),
        muted,
    )));
    lines.push(Line::default());
    if let Some(status) = &s.status {
        match status {
            Ok(msg) => lines.push(Line::from(Span::styled(msg.clone(), cyan))),
            Err(msg) => lines.push(Line::from(Span::styled(format!("Failed: {msg}"), red))),
        }
        lines.push(Line::default());
    }
    if s.pending {
        lines.push(Line::from(Span::styled(
            format!(
                "{} Waiting for OAuth response...",
                spinner_glyph(s.spinner_tick)
            ),
            yellow,
        )));
        lines.push(Line::default());
    }
    if s.authorize_url.is_some() {
        lines.push(Line::from(Span::styled(
            "Open this URL in a browser, then paste the callback URL or code below.".to_string(),
            muted,
        )));
        lines.push(Line::from(vec![
            Span::styled("Open: ", muted),
            Span::styled(
                "open xai.com authorization page",
                cyan.add_modifier(Modifier::UNDERLINED),
            ),
        ]));
        lines.push(Line::from(Span::styled("c copy URL".to_string(), muted)));
        lines.push(Line::default());
    }
    if s.paste_focused {
        lines.push(Line::from(Span::styled(
            "Paste callback URL, ?code=...&state=..., or bare code:".to_string(),
            muted,
        )));
        lines.push(Line::from(vec![
            Span::styled(s.manual_input.text().to_string(), cyan),
            crate::tui::settings::shell::cursor_marker_span(),
        ]));
        return;
    }
    let opts: &[&str] = if OAuthFlowView::Grok(s).confirming() {
        &["continue"]
    } else if s.pending {
        &["paste code manually", "skip / continue"]
    } else {
        &["log in", "manual paste", "skip / continue"]
    };
    for (i, label) in opts.iter().enumerate() {
        let marker = if i == s.cursor { "▸ " } else { "  " };
        let style = if i == s.cursor {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(format!("[{label}]"), style),
        ]));
    }
}

pub(super) fn handle_device_code_oauth_key(
    key: KeyEvent,
    s: &mut DeviceCodeOAuthState,
) -> (bool, Option<OAuthActionRequest>) {
    if matches!(key.code, KeyCode::Char('c')) {
        copy_oauth_url_with(
            s.pending
                .as_ref()
                .map(|login| login.verification_uri.as_str()),
            &mut s.status,
            crate::clipboard::copy_plain,
        );
        return (false, None);
    }
    if matches!(key.code, KeyCode::Char('y')) {
        copy_oauth_url_with(
            s.pending.as_ref().map(|login| login.user_code.as_str()),
            &mut s.status,
            crate::clipboard::copy_plain,
        );
        return (false, None);
    }
    if s.polling && matches!(key.code, KeyCode::Esc) {
        s.polling = false;
        s.status = Some(Ok("Codex OAuth polling cancelled".to_string()));
        return (false, Some(OAuthActionRequest::CodexCancel));
    }
    match key.code {
        KeyCode::Esc => (true, Some(OAuthActionRequest::CodexCancel)),
        KeyCode::Up | KeyCode::Char('k') => {
            let len = OAuthFlowView::Codex(s).option_count();
            s.cursor = oauth_option_cursor_prev(s.cursor, len);
            (false, None)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let len = OAuthFlowView::Codex(s).option_count();
            s.cursor = oauth_option_cursor_next(s.cursor, len);
            (false, None)
        }
        KeyCode::Enter => {
            if OAuthFlowView::Codex(s).confirming() {
                s.cursor = 0;
                return (false, None);
            }
            if s.cursor == 0 {
                if s.polling {
                    return (false, None);
                }
                if let Some(login) = s.pending.clone() {
                    s.polling = true;
                    s.status = Some(Ok("Waiting for Codex approval...".to_string()));
                    return (false, Some(OAuthActionRequest::CodexPoll(login)));
                } else {
                    s.polling = true;
                    s.status = Some(Ok("Requesting Codex device code...".to_string()));
                    return (false, Some(OAuthActionRequest::CodexBegin));
                }
            }
            (false, None)
        }
        _ => (false, None),
    }
}

fn render_codex_oauth_body(lines: &mut Vec<Line<'static>>, s: &DeviceCodeOAuthState) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let green = Style::default().fg(Color::Green);
    let red = Style::default().fg(Color::Red);
    let cyan = Style::default().fg(Color::Cyan);

    lines.push(Line::from(vec![
        Span::styled("Status: ", muted),
        Span::styled(
            if s.logged_in {
                "logged in"
            } else {
                "not logged in"
            }
            .to_string(),
            if s.logged_in { green } else { red },
        ),
    ]));
    lines.push(Line::from(Span::styled(
        "Uses your ChatGPT Plus/Pro subscription quota via OpenAI's documented Codex agent login."
            .to_string(),
        muted,
    )));
    lines.push(Line::from(Span::styled(
        "Separate from the Codex CLI credential store; re-login if CLI use causes refresh-token contention."
            .to_string(),
        muted,
    )));
    lines.push(Line::default());
    if let Some(status) = &s.status {
        match status {
            Ok(msg) => lines.push(Line::from(Span::styled(msg.clone(), cyan))),
            Err(msg) => lines.push(Line::from(Span::styled(format!("Failed: {msg}"), red))),
        }
        lines.push(Line::default());
    }
    if let Some(login) = &s.pending {
        lines.push(Line::from(Span::styled(
            "Open this URL in any browser, including a different machine from this terminal."
                .to_string(),
            muted,
        )));
        lines.push(Line::from(vec![
            Span::styled("Open: ", muted),
            Span::styled(
                login.verification_uri.clone(),
                cyan.add_modifier(Modifier::UNDERLINED),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Code: ", muted),
            Span::styled(login.user_code.clone(), yellow.add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from(Span::styled(
            "Polling starts automatically. c copies the URL; y copies the user code.".to_string(),
            muted,
        )));
        lines.push(Line::default());
    }
    if s.polling {
        lines.push(Line::from(Span::styled(
            format!("{} Waiting for approval...", spinner_glyph(s.spinner_tick)),
            yellow,
        )));
        lines.push(Line::default());
    }
    let opts: &[&str] = if OAuthFlowView::Codex(s).confirming() {
        &["continue"]
    } else if s.pending.is_some() {
        &["poll for approval", "skip / continue"]
    } else {
        &["log in", "skip / continue"]
    };
    for (i, label) in opts.iter().enumerate() {
        let marker = if i == s.cursor { "▸ " } else { "  " };
        let style = if i == s.cursor {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(format!("[{label}]"), style),
        ]));
    }
}
