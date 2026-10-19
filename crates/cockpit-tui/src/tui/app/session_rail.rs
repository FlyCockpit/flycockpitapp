use super::*;
use crate::tui::async_action::AsyncActionKind;
use crate::tui::session_rail::RailOutcome;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

impl App {
    pub(super) fn is_session_rail_focus_chord(key: &KeyEvent) -> bool {
        key.modifiers.contains(KeyModifiers::CONTROL)
            && !key
                .modifiers
                .intersects(KeyModifiers::SHIFT | KeyModifiers::ALT)
            && matches!(key.code, KeyCode::Char('j') | KeyCode::Char('J'))
    }

    pub(super) fn focus_session_rail_search(&mut self) {
        let worktree = self.resolved_worktree_root();
        let previous_scope = self.session_rail.root_request();
        self.session_rail
            .set_project_scope(worktree.as_deref(), &self.launch.cwd);
        if self.session_rail.set_daemon_connected(
            self.sessions_daemon_endpoint().is_some() || self.sessions_daemon_socket().is_some(),
        ) {
            self.abort_session_rail_runner_actions(false);
        }
        self.session_rail
            .set_use_emojis(self.config_snapshot.extended.tui.use_emojis);
        self.session_rail.focus_search();
        if self.session_rail.needs_initial_list() || self.session_rail.daemon_connected() {
            if previous_scope != self.session_rail.root_request() {
                self.start_sessions_list_action();
            } else {
                self.request_session_rail_refresh();
            }
        }
    }

    pub(super) fn maybe_start_session_rail_list(&mut self) {
        if !self.first_paint_completed {
            return;
        }
        self.session_rail
            .set_attachment(self.local_session_draft, self.launch.session_id);
        let connected =
            self.sessions_daemon_endpoint().is_some() || self.sessions_daemon_socket().is_some();
        if self.session_rail.set_daemon_connected(connected) {
            self.abort_session_rail_runner_actions(false);
        }
        if connected
            && (self.session_rail.needs_initial_list()
                || self.session_rail_refresh_needed
                || Instant::now() >= self.session_rail_next_refresh)
        {
            self.request_session_rail_refresh();
        }
    }

    /// Timer and event refreshes coalesce behind all reads in the current
    /// generation. Only scope/search/attachment changes replace those reads.
    pub(super) fn request_session_rail_refresh(&mut self) {
        self.session_rail_refresh_needed = true;
        // drain_completed removes all pending owners before any reducer runs.
        // A routine refresh from an earlier completion must wait for the rest
        // of that batch to publish. The next wake admits the coalesced refresh.
        if self.reducing_async_action_batch {
            return;
        }
        // Outside reduction, pending includes completed-but-undrained reads.
        // Expired/aborted reads settle without a payload and cannot strand us.
        let pending = ["sessions.list", "sessions.live", "sessions.preview"]
            .into_iter()
            .any(|kind| {
                self.async_actions
                    .has_pending_kind(&AsyncActionKind::DaemonRpc(kind))
            });
        if !pending {
            self.start_sessions_list_action();
        }
    }

    pub(super) fn invalidate_session_rail_for_reconnect(&mut self) {
        self.session_rail.set_daemon_connected(true);
        self.session_rail.invalidate_for_reconnect();
        self.abort_session_rail_runner_actions(true);
        if self.first_paint_completed {
            self.start_sessions_list_action();
        }
    }

    /// Abort in-flight rail RPCs. Projection reads always abort. Write RPCs
    /// (favorite and archive/delete/unarchive) abort only on reconnect or
    /// attachment epoch change so a disconnect can still settle a paired
    /// intent.
    pub(super) fn abort_session_rail_runner_actions(&mut self, include_writes: bool) {
        self.async_actions
            .abort_kind(&AsyncActionKind::DaemonRpc("sessions.list"));
        self.async_actions
            .abort_kind(&AsyncActionKind::DaemonRpc("sessions.live"));
        self.async_actions
            .abort_kind(&AsyncActionKind::DaemonRpc("sessions.preview"));
        self.async_actions
            .abort_kind(&AsyncActionKind::DaemonRpc("sessions.inbox"));
        if include_writes {
            self.async_actions
                .abort_kind(&AsyncActionKind::DaemonRpc("sessions.favorite"));
            self.async_actions
                .abort_kind(&AsyncActionKind::DaemonRpc("sessions.mutation"));
        }
    }

    pub(super) fn apply_session_rail_outcome(&mut self, outcome: Option<RailOutcome>) -> bool {
        match outcome {
            None => false,
            Some(RailOutcome::Unfocus) => true,
            Some(RailOutcome::ToggleVisibility) => {
                self.toggle_session_sidebar_from_chord();
                true
            }
            Some(RailOutcome::NewSession) => {
                self.pending_new_session = true;
                true
            }
            Some(RailOutcome::Resume(session_id)) => {
                self.resume_session(session_id);
                true
            }
            Some(RailOutcome::LoadList) => {
                self.start_sessions_list_action();
                true
            }
            Some(RailOutcome::RefreshList) => {
                self.request_session_rail_refresh();
                true
            }
            Some(RailOutcome::LoadPreview {
                session_id,
                before_seq,
            }) => {
                self.start_sessions_preview_action(session_id, before_seq);
                true
            }
            Some(RailOutcome::LoadInbox { main_session_id }) => {
                self.start_sessions_inbox_action(main_session_id);
                true
            }
            Some(RailOutcome::Mutate(request)) => {
                self.start_sessions_mutation_action(*request);
                true
            }
            Some(RailOutcome::SetFavorite {
                session_id,
                favorite,
                canonical_root,
            }) => {
                self.start_sessions_favorite_action(session_id, favorite, canonical_root);
                true
            }
        }
    }

    pub(super) fn handle_session_rail_key(&mut self, key: KeyEvent) -> bool {
        if !self.session_rail.is_focused() {
            return false;
        }
        let outcome = self.session_rail.handle_key(key);
        self.apply_session_rail_outcome(outcome);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::session_rail::{
        COMPACT_AFFORDANCE_WIDTH, COMPACT_BREAKPOINT, RailLayoutMode, WIDE_BREAKPOINT,
    };
    use cockpit_proto::SessionSummary;
    use crossterm::event::{KeyEventKind, KeyEventState};
    use ratatui::{Terminal, backend::TestBackend};
    use uuid::Uuid;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
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

    fn configured_app(tmp: &tempfile::TempDir) -> (App, cockpit_test_support::TestEnvGuard) {
        let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit).unwrap();
        cockpit_config::config::dirs::ensure_global_config_dir().unwrap();
        std::fs::write(
            cockpit.join("config.json"),
            r#"{"active_model":{"provider":"p","model":"m"}}"#,
        )
        .unwrap();
        let provider_dir = cockpit.join("providers");
        std::fs::create_dir_all(&provider_dir).unwrap();
        std::fs::write(
            provider_dir.join("p.json"),
            r#"{"url":"https://example.test","models":[{"id":"m"}]}"#,
        )
        .unwrap();
        let app = cockpit_config::trust::with_workspace_trust_policy(
            super::super::trusted_workspace_policy_for_tests(tmp.path()),
            || App::new(Some(tmp.path()), false),
        );
        (app, env)
    }

    fn summary(id: Uuid, last_active: i64) -> SessionSummary {
        SessionSummary {
            session_id: id,
            session_entry_mode: "code".into(),
            short_id: "abc123".into(),
            project_root: "/proj/alpha".into(),
            project_id: "pid".into(),
            started_at_unix_ms: 0,
            last_active_at_unix_ms: last_active,
            turns: 0,
            active_agent: "builder".into(),
            title: Some(format!("session-{id}")),
            description: None,
            parent_session_id: None,
            fork_point_turn_id: None,
            is_assistant_thread: false,
            fork_count: 0,
            descendant_count: 0,
            last_viewed_at_unix_ms: None,
            latest_activity_at_unix_ms: None,
            open_interrupts: 0,
            activity_state: None,
            archived_at_unix_ms: None,
            favorite: false,
            created_by_principal: None,
            shared_with_collaborators: false,
            pin_count: 0,
            assistant_inbox_unread: 0,
            assistant_inbox_latest_source_session_id: None,
            compaction_predecessor_session_id: None,
            compaction_lineage_root_id: None,
            lineage_window_count: 1,
        }
    }

    async fn day2_pending_rail_request(
        incoming: &mut tokio::sync::mpsc::Receiver<
            tokio::sync::oneshot::Sender<Option<cockpit_client::InProcessConnection>>,
        >,
    ) -> (
        cockpit_client::InProcessRequest,
        tokio::sync::mpsc::Receiver<cockpit_client::InProcessRequest>,
        tokio::sync::mpsc::Sender<cockpit_proto::Event>,
    ) {
        use cockpit_client::{InProcessConnection, InProcessRequest};
        use tokio::sync::mpsc;
        let reply = tokio::time::timeout(Duration::from_secs(3), incoming.recv())
            .await
            .unwrap()
            .unwrap();
        let (requests, mut requests_rx) = mpsc::channel::<InProcessRequest>(2);
        let (events_tx, events) = mpsc::channel(1);
        assert!(
            reply
                .send(Some(InProcessConnection { requests, events }))
                .is_ok()
        );
        let readiness = tokio::time::timeout(Duration::from_secs(3), requests_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            readiness.request,
            cockpit_proto::Request::DaemonStatus
        ));
        assert!(
            readiness
                .reply
                .send(Ok(cockpit_proto::Response::Ack))
                .is_ok()
        );
        let request = tokio::time::timeout(Duration::from_secs(3), requests_rx.recv())
            .await
            .unwrap()
            .unwrap();
        (request, requests_rx, events_tx)
    }

    async fn day2_drain_rail_until(app: &mut App, settled: impl Fn(&App) -> bool) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                app.drain_async_actions();
                if settled(app) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("real rail response must settle");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn day2_session_rail_coalesces_timer_and_events_until_list_live_preview_settle() {
        use cockpit_client::{ClientEndpoint, InProcessEndpoint};
        use cockpit_proto::{Request, Response};
        use tokio::sync::mpsc;
        let (connections, mut incoming) = mpsc::channel(4);
        let (sensitive, _sensitive_rx) = mpsc::channel(1);
        let endpoint = ClientEndpoint::InProcess(InProcessEndpoint::new(connections, sensitive));
        let mut app = App::new(None, false);
        app.first_paint_completed = true;
        app.startup_background.daemon_endpoint = Some(endpoint);
        app.session_rail.set_project_scope(None, &app.launch.cwd);
        app.maybe_start_session_rail_list();
        let generation = app.session_rail.list_generation();
        let (list, _list_rx, _list_events) = day2_pending_rail_request(&mut incoming).await;
        assert!(matches!(list.request, Request::ListSessions { .. }));
        app.session_rail_next_refresh = Instant::now() - Duration::from_millis(1);
        app.maybe_start_session_rail_list();
        assert_eq!(
            app.session_rail.list_generation(),
            generation,
            "periodic refresh must not invalidate the still-pending list response"
        );
        assert!(app.session_rail_refresh_needed);
        app.apply_event(TurnEvent::ThinkingStarted {
            agent: "Build".into(),
            turn_id: None,
        });
        app.maybe_start_session_rail_list();
        assert_eq!(app.session_rail.request_counts().list_started, 1);
        let first = Uuid::new_v4();
        let live = Uuid::new_v4();
        let mut row = summary(first, 2);
        row.title = Some("fresh title from real list".into());
        assert!(
            list.reply
                .send(Ok(Response::Sessions {
                    sessions: vec![row, summary(live, 1)]
                }))
                .is_ok()
        );
        day2_drain_rail_until(&mut app, |app| {
            app.session_rail.request_counts().live_in_flight == 1
                && app.session_rail.request_counts().preview_in_flight == 1
        })
        .await;
        assert_eq!(
            app.session_rail
                .session_summary(first)
                .unwrap()
                .title
                .as_deref(),
            Some("fresh title from real list")
        );
        let (read_a, _a_rx, _a_events) = day2_pending_rail_request(&mut incoming).await;
        let (read_b, _b_rx, _b_events) = day2_pending_rail_request(&mut incoming).await;
        let (live_request, preview_request) =
            if matches!(read_a.request, Request::SessionLiveStatus { .. }) {
                (read_a, read_b)
            } else {
                (read_b, read_a)
            };
        assert!(
            matches!(live_request.request, Request::SessionLiveStatus { ref session_ids } if session_ids.contains(&live))
        );
        assert!(
            matches!(preview_request.request, Request::ReadSessionMessages { session_id, .. } if session_id == first)
        );
        app.maybe_start_session_rail_list();
        app.focus_session_rail_search(); // refocusing the same scope is also a refresh
        assert_eq!(
            app.session_rail.list_generation(),
            generation,
            "live and preview fences must survive refresh"
        );
        assert!(
            live_request
                .reply
                .send(Ok(Response::SessionLiveStatus {
                    statuses: vec![cockpit_proto::LiveStatus {
                        session_id: live,
                        has_active_schedules: true,
                        processing: false,
                        project_root: None,
                    }]
                }))
                .is_ok()
        );
        day2_drain_rail_until(&mut app, |app| {
            app.session_rail.request_counts().live_in_flight == 0
        })
        .await;
        assert_eq!(
            app.session_rail.visible_cards()[0].session_id,
            live,
            "real live status must reorder cards"
        );
        app.maybe_start_session_rail_list();
        assert_eq!(
            app.session_rail.list_generation(),
            generation,
            "pending preview retains its generation after live settles"
        );
        assert!(
            preview_request
                .reply
                .send(Ok(Response::SessionMessages {
                    session_id: first,
                    messages: vec![cockpit_proto::SessionMessage {
                        seq: 1,
                        ts_ms: 1,
                        role: cockpit_proto::MessageRole::User,
                        text: "settled preview".into(),
                    }],
                    has_more: false,
                }))
                .is_ok()
        );
        day2_drain_rail_until(&mut app, |app| {
            app.session_rail.request_counts().preview_in_flight == 0
        })
        .await;
        assert_eq!(
            app.session_rail.preview_message_count(),
            1,
            "real preview response must be consumed"
        );
        assert_eq!(app.session_rail.request_counts().list_started, 1);
        // The event during I/O survives even if the timer is no longer due.
        app.session_rail_next_refresh = Instant::now() + Duration::from_secs(60);
        app.maybe_start_session_rail_list();
        assert_eq!(
            app.session_rail.request_counts().list_started,
            2,
            "coalesced refresh fires after settlement"
        );
        assert!(!app.session_rail_refresh_needed);
        let (refresh, _refresh_rx, _refresh_events) =
            day2_pending_rail_request(&mut incoming).await;
        assert!(matches!(refresh.request, Request::ListSessions { .. }));
        assert!(
            refresh
                .reply
                .send(Ok(Response::Sessions { sessions: vec![] }))
                .is_ok()
        );
        day2_drain_rail_until(&mut app, |app| {
            app.session_rail.request_counts().list_in_flight == 0
        })
        .await;
        app.maybe_start_session_rail_list();
        assert_eq!(
            app.session_rail.request_counts().list_started,
            2,
            "coalesced bit is consumed once"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn day2_session_rail_retry_coalesces_behind_pending_preview() {
        use cockpit_client::{ClientEndpoint, InProcessEndpoint};
        use cockpit_proto::{Request, Response};
        use tokio::sync::mpsc;
        let (connections, mut incoming) = mpsc::channel(4);
        let (sensitive, _sensitive_rx) = mpsc::channel(1);
        let endpoint = ClientEndpoint::InProcess(InProcessEndpoint::new(connections, sensitive));
        let mut app = App::new(None, false);
        app.first_paint_completed = true;
        app.startup_background.daemon_endpoint = Some(endpoint);
        let id = Uuid::new_v4();
        seed_rail_sessions(&mut app, vec![summary(id, 1)]);
        app.start_sessions_list_action();
        let generation = app.session_rail.list_generation();
        let started = app.session_rail.request_counts().list_started;
        let (list, _list_rx, _list_events) = day2_pending_rail_request(&mut incoming).await;
        assert!(matches!(list.request, Request::ListSessions { .. }));
        // A real invalid list response leaves confirmed cards and an error;
        // the list consumer still starts their preview.
        assert!(list.reply.send(Ok(Response::Ack)).is_ok());
        day2_drain_rail_until(&mut app, |app| {
            app.session_rail.request_counts().preview_in_flight == 1
        })
        .await;
        assert!(app.session_rail.error().is_some());
        let (preview, _preview_rx, _preview_events) =
            day2_pending_rail_request(&mut incoming).await;
        assert!(
            matches!(preview.request, Request::ReadSessionMessages { session_id, .. } if session_id == id)
        );
        app.session_rail.focus();
        app.handle_session_rail_key(press(KeyCode::Char('r')));
        assert_eq!(
            app.session_rail.list_generation(),
            generation,
            "same-scope retry must preserve pending preview"
        );
        assert_eq!(app.session_rail.request_counts().list_started, started);
        assert!(app.session_rail_refresh_needed);
        assert!(
            preview
                .reply
                .send(Ok(Response::SessionMessages {
                    session_id: id,
                    messages: vec![cockpit_proto::SessionMessage {
                        seq: 1,
                        ts_ms: 1,
                        role: cockpit_proto::MessageRole::User,
                        text: "preview survives retry".into(),
                    }],
                    has_more: false,
                }))
                .is_ok()
        );
        day2_drain_rail_until(&mut app, |app| {
            app.session_rail.request_counts().preview_in_flight == 0
        })
        .await;
        assert_eq!(app.session_rail.preview_message_count(), 1);
        app.maybe_start_session_rail_list();
        assert_eq!(app.session_rail.request_counts().list_started, started + 1);
        let (refresh, _refresh_rx, _refresh_events) =
            day2_pending_rail_request(&mut incoming).await;
        assert!(matches!(refresh.request, Request::ListSessions { .. }));
        assert!(
            refresh
                .reply
                .send(Ok(Response::Sessions { sessions: vec![] }))
                .is_ok()
        );
        day2_drain_rail_until(&mut app, |app| {
            app.session_rail.request_counts().list_in_flight == 0
        })
        .await;
        assert!(!app.session_rail_refresh_needed);
    }

    #[test]
    fn day2_rail_marks_draft_and_requests_fresh_saved_title_and_activity() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut app, _env) = configured_app(&tmp);
        let id = Uuid::new_v4();
        let mut row = summary(id, 1);
        row.title = None;
        seed_rail_sessions(&mut app, vec![row.clone()]);
        app.local_session_draft = true;
        app.session_rail.set_local_draft(true);
        assert!(render_width(&mut app, 140, 40).contains("Draft (unsaved)"));
        app.session_rail_refresh_needed = false;
        app.apply_event(TurnEvent::ThinkingStarted {
            agent: "Build".into(),
            turn_id: None,
        });
        assert!(app.session_rail_refresh_needed);
        row.title = Some("Fix word count".into());
        row.turns = 1;
        row.last_active_at_unix_ms = 2;
        row.activity_state = Some(cockpit_proto::SessionActivityState::InferenceInProgress);
        seed_rail_sessions(&mut app, vec![row]);
        let text = render_width(&mut app, 140, 40);
        assert!(text.contains("Fix word count"), "{text}");
        assert_eq!(app.session_rail.session_summary(id).unwrap().turns, 1);
        assert_eq!(
            app.session_rail.session_summary(id).unwrap().activity_state,
            Some(cockpit_proto::SessionActivityState::InferenceInProgress)
        );
    }

    fn seed_rail_sessions(app: &mut App, sessions: Vec<SessionSummary>) {
        app.session_rail.set_daemon_connected(true);
        assert!(app.session_rail.begin_list());
        let generation = app.session_rail.list_generation();
        let attachment = app.session_rail.attachment_generation();
        app.session_rail
            .apply_sessions_result(generation, attachment, Ok(sessions));
    }

    fn render_width(app: &mut App, width: u16, height: u16) -> String {
        let buffer = render_buffer(app, width, height);
        buffer
            .content()
            .iter()
            .map(|cell| cell.symbol().to_string())
            .collect()
    }

    fn render_buffer(app: &mut App, width: u16, height: u16) -> ratatui::buffer::Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();
        terminal.backend().buffer().clone()
    }

    fn row_text(buf: &ratatui::buffer::Buffer, y: u16, x_start: u16, x_end: u16) -> String {
        let mut out = String::new();
        for x in x_start..x_end {
            out.push_str(buf[(x, y)].symbol());
        }
        out
    }

    #[test]
    fn named_shell_widths_80_79_56_55() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut app, _env) = configured_app(&tmp);
        app.first_paint_completed = true;

        let text80 = render_width(&mut app, 80, 24);
        assert!(
            app.session_rail.rail_area().is_some() || text80.contains("sessions"),
            "80 columns must keep a persistent rail"
        );
        assert!(matches!(
            RailLayoutMode::from_width(80),
            RailLayoutMode::Wide { .. }
        ));
        assert_eq!(WIDE_BREAKPOINT, 80);
        assert_eq!(COMPACT_BREAKPOINT, 56);

        render_width(&mut app, 79, 24);
        let compact = app.session_rail.compact_area();
        assert!(
            compact.is_some_and(|area| area.width == COMPACT_AFFORDANCE_WIDTH)
                || app
                    .session_rail
                    .rail_area()
                    .is_some_and(|area| area.width == COMPACT_AFFORDANCE_WIDTH),
            "79 columns must hide cards and show a compact affordance"
        );

        render_width(&mut app, 56, 24);
        assert!(
            app.session_rail
                .compact_area()
                .is_some_and(|area| area.width == COMPACT_AFFORDANCE_WIDTH)
                || app
                    .session_rail
                    .rail_area()
                    .is_some_and(|area| area.width == COMPACT_AFFORDANCE_WIDTH)
        );

        render_width(&mut app, 55, 24);
        assert!(app.session_rail.rail_area().is_none());
        assert!(app.session_rail.compact_area().is_none());
        app.session_rail.focus();
        render_width(&mut app, 55, 24);
        assert!(
            app.session_rail.rail_area().is_some(),
            "55 columns shows an overlay-sized rail only while focused"
        );
    }

    #[test]
    fn sessions_command_focuses_rail_search() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut app, _env) = configured_app(&tmp);
        assert!(!app.session_rail.is_focused());
        let cmd = *super::super::slash::SLASH_COMMANDS
            .iter()
            .find(|command| command.name == "sessions")
            .expect("/sessions");
        app.execute_slash(cmd);
        assert!(app.session_rail.is_focused());
        assert!(app.session_rail.is_search_focused());
        assert!(!app.overlay.is_open());
    }

    fn popover_chat_body(app: &App, width: u16, height: u16) -> ratatui::layout::Rect {
        let rects = app
            .geometry()
            .layout(ratatui::layout::Rect::new(0, 0, width, height));
        let (_rail, chat_body) = app.session_rail.split_body(rects.body, width);
        chat_body
    }

    fn chat_column_text(buf: &ratatui::buffer::Buffer, rail_right: u16, width: u16) -> String {
        (0..buf.area.height)
            .map(|y| row_text(buf, y, rail_right, width))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn persistent_rail_remains_visible_under_owned_popover_surfaces() {
        let tmp = tempfile::tempdir().unwrap();

        {
            let (mut tools, _env) = configured_app(&tmp);
            let command = *super::super::slash::SLASH_COMMANDS
                .iter()
                .find(|command| command.name == "tools")
                .unwrap();
            tools.execute_slash(command);
            assert!(matches!(tools.overlay, Overlay::Tools(_)));
            let tools_buf = render_buffer(&mut tools, 120, 40);
            let rail = tools.session_rail.rail_area().expect("persistent rail");
            let rail_right = rail.x + rail.width;
            let tools_text = tools_buf
                .content()
                .iter()
                .map(|cell| cell.symbol().to_string())
                .collect::<String>();
            assert!(tools_text.contains("◆ Cockpit"));
            assert!(tools_text.contains("SESSIONS"));
            let chat_has_tools =
                chat_column_text(&tools_buf, rail_right, 120).contains("current agent tools");
            assert!(
                chat_has_tools,
                "tools popover must render in the chat body, not over the rail"
            );
            let chat_body = popover_chat_body(&tools, 120, 40);
            let popover = tools.last_popover_rect_for_tests();
            assert_eq!(
                popover.height,
                tools.geometry().dialog,
                "tools uses the compact product-popover height"
            );
            assert!(popover.height < chat_body.height, "tools stays compact");
            assert!(popover.x >= rail_right, "popover sits in the chat column");
        }

        {
            let (mut quick, _env) = configured_app(&tmp);
            quick.open_quick_dialog();
            assert!(matches!(quick.overlay, Overlay::Quick(_)));
            let quick_geom = quick.geometry();
            assert!(
                quick_geom.dialog > 0,
                "quick overlay owns a bounded dialog height"
            );
            render_buffer(&mut quick, 120, 40);
            let rail = quick.session_rail.rail_area().expect("quick rail");
            let rail_right = rail.x + rail.width;
            let quick_popover = quick.last_popover_rect_for_tests();
            assert_eq!(
                quick_popover.height, quick_geom.dialog,
                "dialog-height overlays keep their declared height"
            );
            assert!(quick_popover.x >= rail_right);
        }

        {
            let (mut settings, _env) = configured_app(&tmp);
            settings.dialog = Dialog::Settings(Box::new(
                crate::tui::settings::SettingsDialog::open(tmp.path().join("config.json")),
            ));
            let settings_buf = render_buffer(&mut settings, 120, 40);
            assert!(settings.session_rail.rail_area().is_some());
            let settings_rail = settings.session_rail.rail_area().expect("settings rail");
            let rail_right = settings_rail.x + settings_rail.width;
            let settings_popover = settings.last_popover_rect_for_tests();
            assert!(settings_popover.x >= rail_right);
            assert!(settings_popover.height > 12);
            assert!(
                chat_column_text(&settings_buf, rail_right, 120).contains("Settings"),
                "settings dialog paints in the chat column beside the rail"
            );
        }

        {
            let (mut picker, _env) = configured_app(&tmp);
            picker.launch.active_model = Some(("p".to_string(), "m".to_string()));
            picker.config_snapshot.providers.providers.insert(
                "p".to_string(),
                cockpit_config::providers::ProviderEntry {
                    models: vec![cockpit_config::providers::ModelEntry {
                        id: "m".to_string(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            );
            picker.handle_key(ctrl('p'));
            assert!(
                picker.composer_controls.picker.is_some(),
                "pill model picker opens through composer controls after #476"
            );
            let picker_buf = render_buffer(&mut picker, 120, 40);
            assert!(picker.session_rail.rail_area().is_some());
            let picker_rail = picker.session_rail.rail_area().expect("picker rail");
            let rail_right = picker_rail.x + picker_rail.width;
            let picker_popover = picker.last_popover_rect_for_tests();
            assert!(picker_popover.x >= rail_right);
            assert!(picker_popover.height > 12);
            assert!(
                chat_column_text(&picker_buf, rail_right, 120).contains('m'),
                "model picker paints in the chat column beside the rail"
            );
        }

        {
            let (mut trust, _env) = configured_app(&tmp);
            trust.dialog = Dialog::open_workspace_trust(cockpit_config::trust::TrustRoot {
                opened_path: tmp.path().to_path_buf(),
                root: tmp.path().to_path_buf(),
                kind: cockpit_config::trust::TrustRootKind::Directory,
            });
            let trust_buf = render_buffer(&mut trust, 120, 40);
            assert!(trust.session_rail.rail_area().is_some());
            let trust_rail = trust.session_rail.rail_area().expect("trust rail");
            let rail_right = trust_rail.x + trust_rail.width;
            let trust_popover = trust.last_popover_rect_for_tests();
            assert!(trust_popover.x >= rail_right);
            assert!(trust_popover.height > 12);
            assert!(
                chat_column_text(&trust_buf, rail_right, 120).contains("trust"),
                "workspace trust dialog paints in the chat column beside the rail"
            );
        }
    }

    #[test]
    fn ctrl_j_focuses_rail_and_escape_returns_to_composer() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut app, _env) = configured_app(&tmp);
        app.composer.insert_str("hello");
        app.handle_key(ctrl('j'));
        assert!(app.session_rail.is_focused());
        assert_eq!(app.composer.text(), "hello");
        app.handle_key(press(KeyCode::Esc));
        assert!(!app.session_rail.is_focused());
        app.handle_key(press(KeyCode::Char('!')));
        assert_eq!(app.composer.text(), "hello!");
    }

    #[test]
    fn alt_arrows_cycle_sessions_without_leaving_rail_focus() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut app, _env) = configured_app(&tmp);
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        seed_rail_sessions(&mut app, vec![summary(first, 20), summary(second, 10)]);
        assert_eq!(app.session_rail.selected_id(), Some(first));

        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::ALT));
        assert_eq!(app.session_rail.selected_id(), Some(second));
        assert!(!app.session_rail.is_focused());

        app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::ALT));
        assert_eq!(app.session_rail.selected_id(), Some(first));
        assert!(!app.session_rail.is_focused());

        // The chord's implicit Enter must actually resume the cycled-to
        // session, not just move the rail selection: with the live-switch
        // seam installed, Alt+↓ leaves a pending resume of `second`.
        let (_outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
        let mut runner = crate::tui::agent_runner::AgentRunner::test_fixture(Default::default());
        runner.install_live_swappable_switch_seam(outcome_rx);
        app.agent_runner = Some(Ok(runner));

        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::ALT));

        assert_eq!(app.session_rail.selected_id(), Some(second));
        assert!(
            matches!(
                app.pending_session_switch_target,
                Some(crate::tui::agent_runner::SessionTarget::Resume {
                    session_id, ..
                }) if session_id == second
            ),
            "Alt+↓ must leave a pending resume of the cycled-to session"
        );
    }

    #[test]
    fn ctrl_b_visibility_survives_a_config_backed_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut first, _env) = configured_app(&tmp);
        assert!(first.session_rail.is_visible());
        first.handle_key(ctrl('b'));
        assert!(!first.session_rail.is_visible());
        assert!(!first.config_snapshot.extended.tui.session_rail_visible);

        first.clear_model_and_config_chrome_for_empty_session();
        let mut attach_extended = first.config_snapshot.extended.clone();
        attach_extended.tui.session_rail_visible = false;
        first.apply_config_snapshot(cockpit_proto::ConfigSnapshot {
            session_id: uuid::Uuid::new_v4(),
            generation: 1,
            extended: attach_extended,
            providers: cockpit_proto::ProviderConfigView::default(),
        });
        assert!(
            !first.session_rail.is_visible(),
            "hide must survive config-snapshot epoch then daemon apply (attach path)"
        );
        assert!(!first.config_snapshot.extended.tui.session_rail_visible);

        let global = cockpit_config::config::dirs::global_config_file().unwrap();
        let persisted = cockpit_config::extended::ExtendedConfigDoc::load(&global)
            .unwrap()
            .config();
        assert!(!persisted.tui.session_rail_visible);
        drop(_env);
        let (mut restarted, _env2) = configured_app(&tmp);
        assert!(
            !restarted.config_snapshot.extended.tui.session_rail_visible,
            "held config must match the persisted hide preference before attach or toggle"
        );
        assert!(
            !restarted.session_rail.is_visible(),
            "App::new reads the persisted global session-rail preference before first paint"
        );

        restarted.handle_key(ctrl('b'));
        assert!(restarted.session_rail.is_visible());
        assert!(restarted.config_snapshot.extended.tui.session_rail_visible);
    }

    #[test]
    fn alt_arrows_switch_sessions_while_an_overlay_pane_is_open() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut app, _env) = configured_app(&tmp);
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        seed_rail_sessions(&mut app, vec![summary(first, 20), summary(second, 10)]);
        // Open a real overlay pane through the router (which-key →
        // scratchpad) so the pane's own modal key handling is in the way.
        app.handle_key(ctrl('k'));
        app.handle_key(press(KeyCode::Char('n')));
        assert!(matches!(app.overlay, Overlay::Notes(_)));

        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::ALT));

        assert_eq!(
            app.session_rail.selected_id(),
            Some(second),
            "Alt+↓ must switch sessions underneath an open overlay pane (excoc tui.rs:189-201)"
        );
        assert!(
            matches!(app.overlay, Overlay::Notes(_)),
            "the session chord does not dismiss the pane"
        );
    }

    #[test]
    fn alt_down_switches_sessions_while_a_composer_picker_is_open() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut app, _env) = configured_app(&tmp);
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        seed_rail_sessions(&mut app, vec![summary(first, 20), summary(second, 10)]);
        let (_outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
        let mut runner = crate::tui::agent_runner::AgentRunner::test_fixture(Default::default());
        runner.install_live_swappable_switch_seam(outcome_rx);
        app.agent_runner = Some(Ok(runner));

        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
        assert!(
            app.composer_controls.picker.is_some(),
            "Ctrl+P opens the model picker before the session chord"
        );

        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::ALT));

        assert_eq!(app.session_rail.selected_id(), Some(second));
        assert!(
            matches!(
                app.pending_session_switch_target,
                Some(crate::tui::agent_runner::SessionTarget::Resume {
                    session_id, ..
                }) if session_id == second
            ),
            "Alt+down must resume the next session instead of navigating the picker"
        );
        assert!(
            app.composer_controls.picker.is_none(),
            "the global session chord dismisses the picker as it falls through"
        );
        assert_eq!(
            app.composer_controls.selection, None,
            "dismissal releases composer-control ownership"
        );
    }

    #[test]
    fn rail_shortcuts_do_not_steal_composer_when_unfocused() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut app, _env) = configured_app(&tmp);
        app.handle_key(press(KeyCode::Char('a')));
        app.handle_key(press(KeyCode::Char('b')));
        assert_eq!(app.composer.text(), "ab");
        assert!(!app.session_rail.is_focused());
    }

    #[test]
    fn startup_does_not_issue_a_list_before_first_paint() {
        let tmp = tempfile::tempdir().unwrap();
        let (app, _env) = configured_app(&tmp);
        assert!(!app.first_paint_completed);
        assert_eq!(app.session_rail.request_counts().list_started, 0);
        assert!(app.session_rail.needs_initial_list() || !app.session_rail.daemon_connected());
    }

    #[test]
    fn no_overlay_sessions_variant_in_production_enum() {
        let tmp = tempfile::tempdir().unwrap();
        let (app, _env) = configured_app(&tmp);
        assert!(matches!(app.overlay, Overlay::None));
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/tui/app/mod.rs"));
        assert!(
            !source.contains("Sessions(crate::tui::sessions_pane::SessionsPane)"),
            "Overlay::Sessions production variant must be removed"
        );
    }

    #[test]
    fn churn_counts_one_list_through_startup_resize_search_reconnect() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut app, _env) = configured_app(&tmp);
        app.first_paint_completed = true;
        app.session_rail.set_daemon_connected(true);
        app.start_sessions_list_action();
        app.start_sessions_list_action();
        assert_eq!(app.session_rail.request_counts().list_in_flight, 1);
        assert_eq!(app.session_rail.request_counts().list_started, 2);

        render_width(&mut app, 80, 24);
        render_width(&mut app, 100, 24);
        assert_eq!(app.session_rail.request_counts().list_in_flight, 1);

        let stale_list = app.session_rail.list_generation();
        let attach = app.session_rail.attachment_generation();
        app.session_rail.focus();
        app.session_rail.handle_key(press(KeyCode::Char('/')));
        app.session_rail.handle_key(press(KeyCode::Char('q')));
        assert_eq!(app.session_rail.request_counts().list_in_flight, 0);
        app.session_rail
            .apply_sessions_result(stale_list, attach, Ok(vec![]));
        assert_eq!(app.session_rail.request_counts().list_in_flight, 0);
        app.session_rail.handle_key(press(KeyCode::Esc));
        app.session_rail.handle_key(press(KeyCode::Esc));

        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        seed_rail_sessions(&mut app, vec![summary(first, 20), summary(second, 10)]);
        app.session_rail.focus();
        let started = app.session_rail.begin_preview(None).expect("preview");
        assert_eq!(started.0, first);
        app.start_sessions_preview_action(started.0, started.1);
        let stale_preview_gen = app.session_rail.list_generation();
        let stale_preview_attach = app.session_rail.attachment_generation();
        app.handle_session_rail_key(press(KeyCode::Down));
        assert_eq!(app.session_rail.selected_id(), Some(second));
        assert_eq!(app.session_rail.request_counts().preview_in_flight, 1);
        assert_eq!(
            app.async_actions
                .pending_kinds()
                .into_iter()
                .filter(|kind| kind == &AsyncActionKind::DaemonRpc("sessions.preview"))
                .count(),
            1
        );
        app.session_rail.apply_preview_result(
            stale_preview_gen,
            stale_preview_attach,
            first,
            None,
            Ok((Vec::new(), false)),
        );
        assert_eq!(
            app.session_rail.request_counts().preview_in_flight,
            1,
            "stale preview for the previous selection must not consume the replacement in-flight slot"
        );
        assert_eq!(app.session_rail.preview_session_id(), Some(second));
        assert_eq!(app.session_rail.preview_message_count(), 0);

        app.session_rail.set_daemon_connected(true);
        assert!(app.session_rail.begin_list());
        let pre_reconnect_gen = app.session_rail.list_generation();
        let pre_reconnect_attach = app.session_rail.attachment_generation();
        app.invalidate_session_rail_for_reconnect();
        assert_eq!(app.session_rail.request_counts().list_in_flight, 1);
        app.session_rail
            .apply_sessions_result(pre_reconnect_gen, pre_reconnect_attach, Ok(vec![]));
        assert_ne!(app.session_rail.list_generation(), pre_reconnect_gen);
        assert!(app.session_rail.request_counts().list_in_flight <= 1);
        assert!(app.session_rail.request_counts().live_in_flight <= 1);
        assert!(app.session_rail.request_counts().preview_in_flight <= 1);
        assert!(app.session_rail.request_counts().favorite_in_flight <= 1);
    }

    #[test]
    fn reconnect_aborts_pending_session_mutation() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut app, _env) = configured_app(&tmp);
        app.first_paint_completed = true;
        seed_rail_sessions(&mut app, vec![summary(Uuid::from_u128(1), 10)]);
        app.session_rail.focus();
        app.handle_session_rail_key(press(KeyCode::Char('d')));
        app.handle_session_rail_key(press(KeyCode::Right));
        app.handle_session_rail_key(press(KeyCode::Enter));
        assert!(app.session_rail.has_unsettled_local_authority());
        assert!(
            app.async_actions
                .pending_kinds()
                .contains(&AsyncActionKind::DaemonRpc("sessions.mutation"))
        );
        app.invalidate_session_rail_for_reconnect();
        assert!(!app.session_rail.has_unsettled_local_authority());
        assert!(
            !app.async_actions
                .pending_kinds()
                .contains(&AsyncActionKind::DaemonRpc("sessions.mutation"))
        );
    }

    #[test]
    fn attachment_change_aborts_pending_session_mutation() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut app, _env) = configured_app(&tmp);
        app.first_paint_completed = true;
        seed_rail_sessions(&mut app, vec![summary(Uuid::from_u128(1), 10)]);
        app.session_rail.focus();
        app.handle_session_rail_key(press(KeyCode::Char('d')));
        app.handle_session_rail_key(press(KeyCode::Right));
        app.handle_session_rail_key(press(KeyCode::Enter));
        assert!(app.session_rail.has_unsettled_local_authority());
        assert!(
            app.async_actions
                .pending_kinds()
                .contains(&AsyncActionKind::DaemonRpc("sessions.mutation"))
        );
        app.session_rail.discard_for_attachment_change();
        app.abort_session_rail_runner_actions(true);
        assert!(!app.session_rail.has_unsettled_local_authority());
        assert!(
            !app.async_actions
                .pending_kinds()
                .contains(&AsyncActionKind::DaemonRpc("sessions.mutation"))
        );
    }

    #[test]
    fn overlay_rail_masks_transcript_hits() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
        use ratatui::layout::Rect;

        let tmp = tempfile::tempdir().unwrap();
        let (mut app, _env) = configured_app(&tmp);
        app.mouse_capture = true;
        app.session_rail.focus();
        render_width(&mut app, 55, 24);
        let rail = app.session_rail.rail_area().expect("focused overlay rail");
        let hidden = Rect {
            x: rail.x,
            y: rail.y.saturating_add(1),
            width: rail.width.clamp(1, 8),
            height: 1,
        };
        app.link_registry
            .register(hidden, "https://example.invalid/hidden", "hidden");
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: hidden.x,
            row: hidden.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(
            app.pending_link_activation.is_none(),
            "hidden transcript links under the overlay rail must not activate"
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn review_r2_same_batch_inbox_refresh_must_not_drop_completed_list() {
        use cockpit_client::{ClientEndpoint, InProcessEndpoint};
        use cockpit_proto::{Request, Response};
        use tokio::sync::mpsc;
        let (connections, mut incoming) = mpsc::channel(4);
        let (sensitive, _sensitive_rx) = mpsc::channel(1);
        let mut app = App::new(None, false);
        app.first_paint_completed = true;
        app.startup_background.daemon_endpoint = Some(ClientEndpoint::InProcess(
            InProcessEndpoint::new(connections, sensitive),
        ));
        app.maybe_start_session_rail_list();
        let generation = app.session_rail.list_generation();
        let (list, _list_rx, _list_events) = day2_pending_rail_request(&mut incoming).await;
        assert!(matches!(list.request, Request::ListSessions { .. }));
        let id = Uuid::new_v4();
        app.start_sessions_inbox_action(id);
        let (inbox, _inbox_rx, _inbox_events) = day2_pending_rail_request(&mut incoming).await;
        assert!(
            matches!(inbox.request, Request::ReadAssistantInbox { main_session_id, .. } if main_session_id == id)
        );
        let notifier = app.async_actions.notifier();
        assert!(
            inbox
                .reply
                .send(Ok(Response::AssistantInbox {
                    main_session_id: id,
                    items: vec![]
                }))
                .is_ok()
        );
        tokio::time::timeout(Duration::from_secs(3), notifier.notified())
            .await
            .unwrap();
        let mut row = summary(id, 2);
        row.title = Some("completed list data must be consumed".into());
        assert!(
            list.reply
                .send(Ok(Response::Sessions {
                    sessions: vec![row]
                }))
                .is_ok()
        );
        tokio::time::timeout(Duration::from_secs(3), notifier.notified())
            .await
            .unwrap();
        // Both terminal payloads are queued. The real App drain removes all
        // completed actions before applying inbox first and list second.
        app.drain_async_actions();
        let after = app.session_rail.list_generation();
        let title = app
            .session_rail
            .session_summary(id)
            .and_then(|row| row.title.clone());
        let started = app.session_rail.request_counts().list_started;
        drop(incoming);
        assert_eq!(
            after, generation,
            "same-batch refresh must retain the completed list fence until adoption"
        );
        assert_eq!(
            title.as_deref(),
            Some("completed list data must be consumed"),
            "a successful list response must publish its rows"
        );
        assert_eq!(
            started, 1,
            "same-scope refresh waits until result consumption"
        );
    }
    // Real RPCs finish in a controlled order before one real App drain. A
    // mutation/inbox refresh producer must not replace any later read payload.
    async fn day2_same_batch_rail_refresh(mutation_first: bool) {
        use cockpit_client::{ClientEndpoint, InProcessEndpoint};
        use cockpit_proto::{Request, Response};
        use tokio::sync::mpsc;
        let (connections, mut incoming) = mpsc::channel(4);
        let (sensitive, _sensitive_rx) = mpsc::channel(1);
        let mut app = App::new(None, false);
        app.first_paint_completed = true;
        app.startup_background.daemon_endpoint = Some(ClientEndpoint::InProcess(
            InProcessEndpoint::new(connections, sensitive),
        ));
        let first = Uuid::new_v4();
        let live = Uuid::new_v4();
        seed_rail_sessions(&mut app, vec![summary(first, 2), summary(live, 1)]);
        app.start_sessions_list_action();
        let generation = app.session_rail.list_generation();
        let started = app.session_rail.request_counts().list_started;
        let (list, _list_rx, _list_events) = day2_pending_rail_request(&mut incoming).await;
        assert!(matches!(list.request, Request::ListSessions { .. }));
        let notifier = app.async_actions.notifier();

        if mutation_first {
            app.session_rail.focus();
            app.handle_session_rail_key(press(KeyCode::Char('d')));
            app.handle_session_rail_key(press(KeyCode::Right));
            app.handle_session_rail_key(press(KeyCode::Enter));
            assert!(app.session_rail.has_unsettled_local_authority());
        } else {
            app.start_sessions_inbox_action(first);
        }
        let (producer, _producer_rx, _producer_events) =
            day2_pending_rail_request(&mut incoming).await;
        let response = if mutation_first {
            assert!(matches!(producer.request, Request::ArchiveSession { .. }));
            Response::Ack
        } else {
            assert!(matches!(
                producer.request,
                Request::ReadAssistantInbox { .. }
            ));
            Response::AssistantInbox {
                main_session_id: first,
                items: vec![],
            }
        };
        assert!(producer.reply.send(Ok(response)).is_ok());
        tokio::time::timeout(Duration::from_secs(3), notifier.notified())
            .await
            .unwrap();
        let mut row = summary(first, 2);
        row.title = Some("same-batch saved title".into());
        assert!(
            list.reply
                .send(Ok(Response::Sessions {
                    sessions: vec![row, summary(live, 1)]
                }))
                .is_ok()
        );
        tokio::time::timeout(Duration::from_secs(3), notifier.notified())
            .await
            .unwrap();
        app.drain_async_actions();
        assert_eq!(
            app.session_rail.list_generation(),
            generation,
            "producer must not invalidate completed list before adoption"
        );
        assert_eq!(
            app.session_rail
                .session_summary(first)
                .unwrap()
                .title
                .as_deref(),
            Some("same-batch saved title")
        );
        assert_eq!(app.session_rail.request_counts().list_started, started);
        assert!(app.session_rail_refresh_needed);
        assert!(!app.session_rail.has_unsettled_local_authority());

        let (read_a, _a_rx, _a_events) = day2_pending_rail_request(&mut incoming).await;
        let (read_b, _b_rx, _b_events) = day2_pending_rail_request(&mut incoming).await;
        let (live_rpc, preview_rpc) = if matches!(read_a.request, Request::SessionLiveStatus { .. })
        {
            (read_a, read_b)
        } else {
            (read_b, read_a)
        };
        assert!(matches!(
            live_rpc.request,
            Request::SessionLiveStatus { .. }
        ));
        assert!(
            matches!(preview_rpc.request, Request::ReadSessionMessages { session_id, .. } if session_id == first)
        );
        // Now repeat with both live and preview already completed behind the
        // producer, without draining any of the three terminal payloads early.
        if mutation_first {
            app.session_rail.focus();
            app.handle_session_rail_key(press(KeyCode::Char('d')));
            app.handle_session_rail_key(press(KeyCode::Right));
            app.handle_session_rail_key(press(KeyCode::Enter));
            assert!(app.session_rail.has_unsettled_local_authority());
        } else {
            app.start_sessions_inbox_action(first);
        }
        let (producer, _producer2_rx, _producer2_events) =
            day2_pending_rail_request(&mut incoming).await;
        let response = if mutation_first {
            assert!(matches!(producer.request, Request::ArchiveSession { .. }));
            Response::Ack
        } else {
            assert!(matches!(
                producer.request,
                Request::ReadAssistantInbox { .. }
            ));
            Response::AssistantInbox {
                main_session_id: first,
                items: vec![],
            }
        };
        assert!(producer.reply.send(Ok(response)).is_ok());
        tokio::time::timeout(Duration::from_secs(3), notifier.notified())
            .await
            .unwrap();
        assert!(
            live_rpc
                .reply
                .send(Ok(Response::SessionLiveStatus {
                    statuses: vec![cockpit_proto::LiveStatus {
                        session_id: live,
                        has_active_schedules: true,
                        processing: false,
                        project_root: None
                    }]
                }))
                .is_ok()
        );
        tokio::time::timeout(Duration::from_secs(3), notifier.notified())
            .await
            .unwrap();
        assert!(
            preview_rpc
                .reply
                .send(Ok(Response::SessionMessages {
                    session_id: first,
                    messages: vec![cockpit_proto::SessionMessage {
                        seq: 1,
                        ts_ms: 1,
                        role: cockpit_proto::MessageRole::User,
                        text: "same-batch preview".into()
                    }],
                    has_more: false,
                }))
                .is_ok()
        );
        tokio::time::timeout(Duration::from_secs(3), notifier.notified())
            .await
            .unwrap();
        app.drain_async_actions();
        assert_eq!(
            app.session_rail.list_generation(),
            generation,
            "producer must not invalidate completed live/preview before adoption"
        );
        assert_eq!(
            app.session_rail.visible_cards()[0].session_id,
            live,
            "live status must publish its reordering"
        );
        assert_eq!(
            app.session_rail.preview_message_count(),
            1,
            "preview must publish its messages"
        );
        assert_eq!(app.session_rail.request_counts().list_started, started);
        assert!(app.session_rail_refresh_needed);
        assert!(!app.session_rail.has_unsettled_local_authority());
        app.session_rail_next_refresh = Instant::now() + Duration::from_secs(60);
        app.maybe_start_session_rail_list();
        assert_eq!(
            app.session_rail.request_counts().list_started,
            started + 1,
            "one later refresh after adoption"
        );
        assert!(!app.session_rail_refresh_needed);
        let (refresh, _refresh_rx, _refresh_events) =
            day2_pending_rail_request(&mut incoming).await;
        assert!(matches!(refresh.request, Request::ListSessions { .. }));
        assert!(
            refresh
                .reply
                .send(Ok(Response::Sessions { sessions: vec![] }))
                .is_ok()
        );
        day2_drain_rail_until(&mut app, |app| {
            app.session_rail.request_counts().list_in_flight == 0
        })
        .await;
        app.maybe_start_session_rail_list();
        assert_eq!(
            app.session_rail.request_counts().list_started,
            started + 1,
            "settled refresh must not loop"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn day2_session_rail_same_batch_inbox_preserves_list_live_preview() {
        day2_same_batch_rail_refresh(false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn day2_session_rail_same_batch_mutation_preserves_list_live_preview() {
        day2_same_batch_rail_refresh(true).await;
    }
    #[test]
    fn ux4_draft_and_attached_rail_selection_with_two_saved_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut app, _env) = configured_app(&tmp);
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut first_row = summary(first, 2);
        first_row.title = Some("UX4 first saved".into());
        let mut second_row = summary(second, 1);
        second_row.title = Some("UX4 second saved".into());
        seed_rail_sessions(&mut app, vec![first_row.clone(), second_row.clone()]);
        app.launch.session_id = Some(second);
        app.local_session_draft = false;
        let attached_buffer = render_buffer(&mut app, 140, 40);
        let attached = (0..40)
            .map(|y| row_text(&attached_buffer, y, 0, 36))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(attached.contains("+ New session"), "{attached}");
        assert!(
            attached
                .lines()
                .any(|line| line.contains("▌") && line.contains("UX4 second saved")),
            "{attached}"
        );
        assert!(
            !attached
                .lines()
                .any(|line| line.contains("▌") && line.contains("UX4 first saved")),
            "{attached}"
        );
        app.current_session_persisted = true;
        app.pending_new_session = true;
        app.maybe_open_local_session_draft_with_clear(|| Ok(()))
            .unwrap();
        for focused in [false, true] {
            if focused {
                app.session_rail.focus_search();
            }
            seed_rail_sessions(&mut app, vec![first_row.clone(), second_row.clone()]);
            let draft = render_width(&mut app, 140, 40);
            assert!(draft.contains("Draft (unsaved)"), "{draft}");
            assert!(
                !draft
                    .lines()
                    .any(|line| line.contains("▌") && line.contains("UX4")),
                "no saved row may be highlighted: {draft}"
            );
        }
    }
}
