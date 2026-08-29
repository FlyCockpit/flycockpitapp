//! Queue-box controls: class toggles, send-now, edit, cancel, and focus.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use uuid::Uuid;

use super::App;
use cockpit_proto::{QueueDeliveryClass, Request};

impl App {
    pub(super) fn queue_visual_ids(&self) -> Vec<Uuid> {
        self.queue_delivery_groups()
            .into_iter()
            .flat_map(|(_, steering, held)| steering.into_iter().chain(held))
            .map(|item| item.id)
            .collect()
    }

    pub(super) fn queue_has_held(&self) -> bool {
        self.queue
            .iter()
            .any(|item| item.delivery_class == QueueDeliveryClass::Held)
    }

    pub(super) fn queue_box_toggle_label(&self) -> &'static str {
        if self.queue_has_held() {
            "steer all"
        } else {
            "hold all"
        }
    }

    pub(super) fn queue_item_toggle_label(class: QueueDeliveryClass) -> &'static str {
        match class {
            QueueDeliveryClass::Steering => "hold",
            QueueDeliveryClass::Held => "steer",
        }
    }

    pub(super) fn queue_message_revealed(&self, id: Uuid) -> bool {
        self.queue_focus == Some(id)
            || self.queue_hover == Some(id)
            || self
                .button_registry
                .hover()
                .is_some_and(|hover| match hover {
                    crate::tui::button::ButtonId::QueueSendNow { item_id }
                    | crate::tui::button::ButtonId::QueueToggleClass { item_id }
                    | crate::tui::button::ButtonId::QueueEdit { item_id }
                    | crate::tui::button::ButtonId::QueueCancel { item_id } => *item_id == Some(id),
                    _ => false,
                })
    }

    pub(super) fn focus_queue_from_composer(&mut self) -> bool {
        let ids = self.queue_visual_ids();
        let Some(id) = ids.last().copied() else {
            return false;
        };
        self.queue_focus = Some(id);
        true
    }

    pub(super) fn blur_queue_focus(&mut self) {
        self.queue_focus = None;
    }

    pub(super) fn queue_focus_move(&mut self, delta: isize) -> bool {
        let ids = self.queue_visual_ids();
        if ids.is_empty() {
            self.queue_focus = None;
            return false;
        }
        let current = self
            .queue_focus
            .and_then(|id| ids.iter().position(|item| *item == id))
            .unwrap_or(ids.len().saturating_sub(1));
        let next = current as isize + delta;
        if next < 0 || next >= ids.len() as isize {
            self.queue_focus = None;
            return false;
        }
        self.queue_focus = Some(ids[next as usize]);
        true
    }

    pub(super) fn handle_queue_key(&mut self, key: KeyEvent) -> bool {
        if self.queue_focus.is_none() {
            return false;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            || key.modifiers.contains(KeyModifiers::ALT)
        {
            return false;
        }
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        match key.code {
            KeyCode::Esc => {
                self.blur_queue_focus();
                true
            }
            KeyCode::Up => {
                if !self.queue_focus_move(-1) {
                    // The top edge is the explicit box-level edit gesture.
                    // Do not blur and immediately cycle back to the last row:
                    // that made edit-all unreachable from the keyboard.
                    self.blur_queue_focus();
                    self.queue_action_edit(None);
                }
                true
            }
            KeyCode::Down => {
                if !self.queue_focus_move(1) {
                    self.blur_queue_focus();
                }
                true
            }
            KeyCode::Char(c) if shift => match c.to_ascii_lowercase() {
                's' => {
                    self.queue_action_send_now(None);
                    true
                }
                't' => {
                    self.queue_action_toggle(None);
                    true
                }
                'x' => {
                    self.queue_action_cancel(None);
                    true
                }
                _ => true,
            },
            KeyCode::Char('s') => {
                if let Some(id) = self.queue_focus {
                    self.queue_action_send_now(Some(id));
                }
                true
            }
            KeyCode::Char('t') => {
                if let Some(id) = self.queue_focus {
                    self.queue_action_toggle(Some(id));
                }
                true
            }
            KeyCode::Char('e') => {
                if let Some(id) = self.queue_focus {
                    self.queue_action_edit(Some(id));
                }
                true
            }
            KeyCode::Char('x') => {
                if let Some(id) = self.queue_focus {
                    self.queue_action_cancel(Some(id));
                }
                true
            }
            KeyCode::Delete | KeyCode::Backspace if shift => {
                self.queue_action_cancel(None);
                true
            }
            KeyCode::Delete | KeyCode::Backspace => {
                if let Some(id) = self.queue_focus {
                    self.queue_action_cancel(Some(id));
                }
                true
            }
            _ => true,
        }
    }

    pub(super) fn queue_action_send_now(&mut self, item_id: Option<Uuid>) {
        self.send_queue_request(Request::SendNowQueuedUserMessage {
            queue_item_id: item_id,
        });
    }

    pub(super) fn queue_action_toggle(&mut self, item_id: Option<Uuid>) {
        match item_id {
            Some(id) => {
                let Some(item) = self.queue.iter().find(|item| item.id == id) else {
                    return;
                };
                let delivery_class = item.delivery_class.toggled();
                self.send_queue_request(Request::SetQueuedUserMessageClass {
                    queue_item_id: id,
                    delivery_class,
                    replacement: None,
                });
            }
            None => {
                let delivery_class = if self.queue_has_held() {
                    QueueDeliveryClass::Steering
                } else {
                    QueueDeliveryClass::Held
                };
                self.send_queue_request(Request::PromoteQueuedUserMessages { delivery_class });
            }
        }
    }

    pub(super) fn queue_promote_all(&mut self, delivery_class: QueueDeliveryClass) {
        self.send_queue_request(Request::PromoteQueuedUserMessages { delivery_class });
    }

    pub(super) fn queue_action_edit(&mut self, item_id: Option<Uuid>) {
        match item_id {
            Some(id) => self.edit_one_queued_message(id),
            None => {
                if self.pending_queue_edit_all_retrieval {
                    self.show_toast(
                        super::input::QUEUE_EDIT_PENDING_NOTICE,
                        super::ToastKind::Info,
                    );
                    return;
                }
                if self.pending_queue_edit_item_id.is_some() {
                    self.show_toast(
                        "finish or cancel the current queued-message edit first",
                        super::ToastKind::Info,
                    );
                    return;
                }
                if !self.composer.is_empty() {
                    self.show_toast(
                        "send or clear the current draft before editing queued messages",
                        super::ToastKind::Info,
                    );
                    return;
                }
                let _ = self.edit_queued_messages();
            }
        }
    }

    pub(super) fn queue_action_cancel(&mut self, item_id: Option<Uuid>) {
        match item_id {
            Some(id) => {
                self.send_queue_request(Request::RemoveQueuedUserMessage { queue_item_id: id });
            }
            None => {
                self.send_queue_request(Request::RemoveEditableQueuedUserMessages {
                    target_id: None,
                });
            }
        }
    }

    fn edit_one_queued_message(&mut self, id: Uuid) {
        if self.pending_queue_edit_all_retrieval {
            self.show_toast(
                super::input::QUEUE_EDIT_PENDING_NOTICE,
                super::ToastKind::Info,
            );
            return;
        }
        if self.pending_queue_edit_item_id.is_some() {
            self.show_toast(
                "finish or cancel the current queued-message edit first",
                super::ToastKind::Info,
            );
            return;
        }
        if !self.composer.is_empty() {
            self.show_toast(
                "send or clear the current draft before editing a queued message",
                super::ToastKind::Info,
            );
            return;
        }
        let Some(item) = self.queue.iter().find(|item| item.id == id).cloned() else {
            return;
        };
        if self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .is_none()
        {
            self.show_toast(
                "queued-message edit is unavailable until the session is connected",
                super::ToastKind::Info,
            );
            return;
        }
        let operation_id = Uuid::new_v4();
        self.pending_queue_edit_class = Some(item.delivery_class);
        self.pending_queue_edit_item_id = Some(id);
        self.pending_queue_edit_operation_id = Some(operation_id);
        self.pending_queue_edit_commit = false;
        self.pending_queue_edit_reserved = false;
        self.pending_queue_edit_releasing = false;
        self.send_queue_request(Request::SetQueuedUserMessageClass {
            queue_item_id: id,
            delivery_class: item.delivery_class,
            replacement: Some(cockpit_proto::QueueItemReplacement {
                operation_id,
                action: cockpit_proto::QueueEditAction::Reserve,
                text: item.text.clone(),
                display_text: item.display_text.clone(),
                tag_expansions: Vec::new(),
            }),
        });
        let text = item
            .display_text
            .filter(|value| !value.is_empty())
            .unwrap_or(item.text);
        self.replace_composer_buffer(text);
        self.blur_queue_focus();
    }

    pub(super) fn cancel_queued_message_edit(&mut self) -> bool {
        let Some(id) = self.pending_queue_edit_item_id else {
            return false;
        };
        let Some(operation_id) = self.pending_queue_edit_operation_id else {
            return false;
        };
        if self.pending_queue_edit_releasing {
            return true;
        }
        let Some(item) = self.queue.iter().find(|item| item.id == id).cloned() else {
            self.clear_pending_queue_edit_state();
            self.clear_composer_buffer();
            return true;
        };
        self.send_queue_request(Request::SetQueuedUserMessageClass {
            queue_item_id: id,
            delivery_class: item.delivery_class,
            replacement: Some(cockpit_proto::QueueItemReplacement {
                operation_id,
                action: cockpit_proto::QueueEditAction::Release,
                text: item.text,
                display_text: item.display_text,
                tag_expansions: Vec::new(),
            }),
        });
        self.pending_queue_edit_releasing = true;
        true
    }

    pub(super) fn retry_pending_queue_edit(&mut self) {
        if let Some(request) = self.pending_queue_edit_request.clone() {
            self.send_queue_request(request);
        }
    }

    pub(super) fn send_queue_request(&mut self, request: Request) {
        let edit_correlation = match &request {
            Request::SetQueuedUserMessageClass {
                queue_item_id,
                replacement: Some(replacement),
                ..
            } => Some((*queue_item_id, replacement.operation_id, replacement.action)),
            _ => None,
        };
        if self.pending_queue_edit_all_retrieval {
            self.show_toast(
                super::input::QUEUE_EDIT_PENDING_NOTICE,
                super::ToastKind::Info,
            );
            return;
        }
        if let Some(pending_item_id) = self.pending_queue_edit_item_id
            && !edit_correlation.is_some_and(|(item_id, operation_id, _)| {
                item_id == pending_item_id
                    && Some(operation_id) == self.pending_queue_edit_operation_id
            })
        {
            self.show_toast(
                "queue controls are locked while a queued-message edit is unresolved",
                super::ToastKind::Info,
            );
            return;
        }
        if edit_correlation.is_some() {
            self.pending_queue_edit_request = Some(request.clone());
        }
        let is_edit_reservation = edit_correlation
            .is_some_and(|(_, _, action)| action == cockpit_proto::QueueEditAction::Reserve);
        let Some(attached) = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .map(|runner| runner.attached_request_binding())
        else {
            let notice = if is_edit_reservation {
                "queued-message edit reservation is waiting for the session to reconnect"
            } else if edit_correlation.is_some() {
                "queued-message edit is waiting for the session to reconnect"
            } else {
                "queue controls are unavailable until the session is connected"
            };
            self.show_toast(notice, super::ToastKind::Info);
            return;
        };
        let action_key = match &request {
            Request::SetQueuedUserMessageClass { queue_item_id, .. }
            | Request::RemoveQueuedUserMessage { queue_item_id } => {
                format!("queue.control.{queue_item_id}")
            }
            Request::SendNowQueuedUserMessage {
                queue_item_id: Some(queue_item_id),
            } => format!("queue.control.{queue_item_id}"),
            _ => "queue.control".to_string(),
        };
        let action_kind = match &request {
            Request::SetQueuedUserMessageClass {
                replacement: Some(replacement),
                ..
            } if replacement.action == cockpit_proto::QueueEditAction::Reserve => {
                crate::tui::async_action::AsyncActionKind::DaemonRpc("queue.edit.reservation")
            }
            Request::SetQueuedUserMessageClass {
                replacement: Some(replacement),
                ..
            } if replacement.action == cockpit_proto::QueueEditAction::Commit => {
                crate::tui::async_action::AsyncActionKind::DaemonRpc("queue.edit.commit")
            }
            Request::SetQueuedUserMessageClass {
                replacement: Some(replacement),
                ..
            } if replacement.action == cockpit_proto::QueueEditAction::Release => {
                crate::tui::async_action::AsyncActionKind::DaemonRpc("queue.edit.release")
            }
            _ => crate::tui::async_action::AsyncActionKind::DaemonRpc("queue.control"),
        };
        self.async_actions.start_serialized(
            action_kind,
            crate::tui::async_action::AsyncActionKey::new(action_key),
            async move {
                let mut last_error = "queue edit response was not correlated".to_string();
                for _ in 0..8 {
                    match attached.request(request.clone()).await {
                        Ok(response) => {
                            let correlated = match (edit_correlation, &response) {
                                (
                                    Some((expected_item, expected_operation, expected_action)),
                                    cockpit_proto::Response::SetQueuedUserMessageClassResult {
                                        queue_item_id,
                                        edit_operation_id,
                                        edit_action,
                                        ..
                                    },
                                ) => {
                                    *queue_item_id == expected_item
                                        && *edit_operation_id == Some(expected_operation)
                                        && *edit_action == Some(expected_action)
                                }
                                (None, _) => true,
                                _ => false,
                            };
                            if correlated {
                                return Ok(
                                    crate::tui::async_action::AsyncActionPayload::DaemonResponse(
                                        Box::new(response),
                                    ),
                                );
                            }
                            last_error = "queue edit response correlation mismatch".to_string();
                        }
                        Err(error) if edit_correlation.is_none() => return Err(error),
                        Err(error) => last_error = error,
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
                Err(last_error)
            },
        );
    }

    pub(super) fn update_queue_pointer(&mut self, mouse: crossterm::event::MouseEvent) {
        let hit = self.queue_row_hits.iter().find_map(|(id, rect)| {
            (mouse.column >= rect.x
                && mouse.column < rect.right()
                && mouse.row >= rect.y
                && mouse.row < rect.bottom())
            .then_some(*id)
        });
        self.queue_hover = hit;
        if matches!(
            mouse.kind,
            crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left)
        ) && let Some(id) = hit
        {
            self.queue_focus = Some(id);
        }
    }

    pub(super) fn apply_queue_control_response(&mut self, response: cockpit_proto::Response) {
        if let cockpit_proto::Response::SetQueuedUserMessageClassResult {
            queue_item_id,
            applied,
            edit_operation_id,
            edit_action,
            item,
            reason,
            ..
        } = &response
            && Some(*queue_item_id) == self.pending_queue_edit_item_id
            && *edit_operation_id == self.pending_queue_edit_operation_id
        {
            match (*edit_action, *applied) {
                (Some(cockpit_proto::QueueEditAction::Reserve), true) => {
                    self.pending_queue_edit_reserved = true;
                    self.pending_queue_edit_request = None;
                }
                (
                    Some(
                        cockpit_proto::QueueEditAction::Commit
                        | cockpit_proto::QueueEditAction::Release,
                    ),
                    true,
                ) if item
                    .as_ref()
                    .is_some_and(|item| Some(item.id) == self.pending_queue_edit_item_id) =>
                {
                    self.clear_pending_queue_edit_state();
                    self.clear_composer_buffer();
                    self.draft_generation = self.draft_generation.saturating_add(1);
                }
                (Some(cockpit_proto::QueueEditAction::Commit), false) => {
                    // A lease may expire between reserve and commit. The
                    // daemon retains the original queue item, while the
                    // composer now contains the user's only copy of the edit.
                    // Reconcile the expired identity without discarding that
                    // draft so it can be reviewed or submitted again.
                    self.clear_pending_queue_edit_state();
                    self.show_toast(
                        format!(
                            "queued-message edit was not applied ({reason:?}); the original remains queued and the edited draft was preserved"
                        ),
                        super::ToastKind::Info,
                    );
                }
                (_, false) => {
                    // This is an authoritative terminal rejection, not an
                    // ambiguous transport failure. Discard the duplicated
                    // composer projection so it cannot be submitted as a new
                    // message after the daemon may have started the original.
                    self.clear_pending_queue_edit_state();
                    self.clear_composer_buffer();
                    self.show_toast(
                        format!("queued-message edit was not applied: {reason:?}"),
                        super::ToastKind::Info,
                    );
                }
                _ => {}
            }
        }
        // QueueUpdated events own the authoritative queue mirror. RPC
        // snapshots travel on an independent channel and may be older than a
        // folded/removal event, so applying them here could resurrect items.
        if let Some(id) = self.queue_focus
            && !self.queue.iter().any(|item| item.id == id)
        {
            self.queue_focus = self.queue_visual_ids().last().copied();
        }
    }

    pub(super) fn fail_pending_queue_edit(&mut self, error: &str) {
        self.show_toast(
            format!(
                "queue edit remains reserved; it will retry after reconnect, or Esc will release it: {error}"
            ),
            super::ToastKind::Info,
        );
    }

    fn clear_pending_queue_edit_state(&mut self) {
        self.pending_queue_edit_item_id = None;
        self.pending_queue_edit_operation_id = None;
        self.pending_queue_edit_request = None;
        self.pending_queue_edit_class = None;
        self.pending_queue_edit_commit = false;
        self.pending_queue_edit_reserved = false;
        self.pending_queue_edit_releasing = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::input;
    use cockpit_proto::{QueueItemStatus, QueueTarget};

    fn item(text: &str, class: QueueDeliveryClass) -> cockpit_proto::QueueItem {
        cockpit_proto::QueueItem {
            id: Uuid::new_v4(),
            status: QueueItemStatus::Queued,
            text: text.to_string(),
            display_text: None,
            target: QueueTarget::root("Build"),
            delivery_class: class,
            send_now: false,
        }
    }

    fn apply_snapshot(app: &mut App, queue: Vec<cockpit_proto::QueueItem>) {
        app.reconcile_queue_update(queue);
    }

    #[test]
    fn toggle_one_moves_class_and_cancel_leaves_others() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let first = item("one", QueueDeliveryClass::Steering);
        let second = item("two", QueueDeliveryClass::Steering);
        let first_id = first.id;
        app.queue.extend([first, second]);
        app.queue_action_toggle(Some(first_id));
        let mut queue = app.queue.clone();
        queue[0].delivery_class = QueueDeliveryClass::Held;
        apply_snapshot(&mut app, queue);
        assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Held);
        assert_eq!(app.queue[1].delivery_class, QueueDeliveryClass::Steering);
        app.queue_action_cancel(Some(first_id));
        let queue = app
            .queue
            .iter()
            .filter(|item| item.id != first_id)
            .cloned()
            .collect();
        apply_snapshot(&mut app, queue);
        assert_eq!(app.queue.len(), 1);
        assert_eq!(app.queue[0].text, "two");
    }

    #[test]
    fn steer_all_promotes_held_messages() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.queue.push(item("held", QueueDeliveryClass::Held));
        app.queue.push(item("steer", QueueDeliveryClass::Steering));
        assert_eq!(app.queue_box_toggle_label(), "steer all");
        app.queue_action_toggle(None);
        let mut queue = app.queue.clone();
        for item in &mut queue {
            item.delivery_class = QueueDeliveryClass::Steering;
        }
        apply_snapshot(&mut app, queue);
        assert!(
            app.queue
                .iter()
                .all(|item| item.delivery_class == QueueDeliveryClass::Steering)
        );
        assert_eq!(app.queue_box_toggle_label(), "hold all");
    }

    #[test]
    fn unattached_queue_control_shows_notice() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let queued = item("one", QueueDeliveryClass::Held);
        let queued_id = queued.id;
        app.queue.push(queued);

        app.queue_action_toggle(Some(queued_id));
        assert!(matches!(
            &app.toast,
            Some(toast) if toast.text == "queue controls are unavailable until the session is connected"
        ));
        assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Held);

        app.queue_action_send_now(Some(queued_id));
        assert!(matches!(
            &app.toast,
            Some(toast) if toast.text == "queue controls are unavailable until the session is connected"
        ));

        app.queue_promote_all(QueueDeliveryClass::Steering);
        assert!(matches!(
            &app.toast,
            Some(toast) if toast.text == "queue controls are unavailable until the session is connected"
        ));
        assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Held);

        app.queue_action_cancel(Some(queued_id));
        assert!(matches!(
            &app.toast,
            Some(toast) if toast.text == "queue controls are unavailable until the session is connected"
        ));
        assert_eq!(app.queue.len(), 1);
    }

    #[test]
    fn unavailable_edit_reservation_keeps_order_and_usable_draft() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let first = item("one", QueueDeliveryClass::Steering);
        let second = item("two", QueueDeliveryClass::Held);
        let first_id = first.id;
        app.queue.extend([first, second]);
        app.queue_action_edit(Some(first_id));
        assert!(app.composer.text().is_empty());
        assert_eq!(app.queue.len(), 2);
        assert_eq!(app.queue[0].text, "one");
        assert_eq!(app.queue[1].text, "two");
        assert!(app.pending_queue_edit_item_id.is_none());
        assert!(app.pending_queue_edit_class.is_none());
    }

    #[test]
    fn edit_one_does_not_replace_an_existing_composer_draft() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let queued = item("queued text", QueueDeliveryClass::Steering);
        let queued_id = queued.id;
        app.queue.push(queued);
        app.replace_composer_buffer("unsubmitted draft");

        app.queue_action_edit(Some(queued_id));

        assert_eq!(app.composer.text(), "unsubmitted draft");
        assert_eq!(app.queue.len(), 1);
        assert_eq!(app.queue[0].id, queued_id);
        assert!(app.pending_queue_edit_item_id.is_none());
    }

    #[test]
    fn edit_all_blocks_submit_while_retrieval_pending() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.queue.push(item("one", QueueDeliveryClass::Steering));
        app.pending_queue_edit_all_retrieval = true;
        app.replace_composer_buffer("concurrent draft");

        assert!(!app.submit_input());
        assert!(matches!(
            &app.toast,
            Some(toast) if toast.text == input::QUEUE_EDIT_PENDING_NOTICE
        ));
        assert_eq!(app.composer.text(), "concurrent draft");
        assert_eq!(app.queue.len(), 1);
    }

    #[test]
    fn edit_all_blocks_queue_mutations_while_retrieval_pending() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let queued = item("one", QueueDeliveryClass::Held);
        let queued_id = queued.id;
        app.queue.push(queued);
        app.pending_queue_edit_all_retrieval = true;

        app.queue_action_toggle(Some(queued_id));

        assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Held);
        assert!(matches!(
            &app.toast,
            Some(toast) if toast.text == input::QUEUE_EDIT_PENDING_NOTICE
        ));
    }

    #[test]
    fn edit_all_merges_composer_draft_when_it_changes_during_retrieval() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.pending_queue_edit_all_retrieval = true;
        app.replace_composer_buffer("typed during retrieval");

        app.apply_queue_edit_outcome(input::QueueEditOutcome::Edited {
            text: "one\n\ntwo".to_string(),
            partial: false,
        });

        assert_eq!(app.composer.text(), "one\n\ntwo\n\ntyped during retrieval");
        assert!(matches!(
            &app.toast,
            Some(toast) if toast.text == "loaded merged queued messages before your composer draft"
        ));
        assert!(!app.pending_queue_edit_all_retrieval);
    }

    #[test]
    fn edit_all_does_not_replace_an_existing_composer_draft() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.queue.push(item("one", QueueDeliveryClass::Steering));
        app.queue.push(item("two", QueueDeliveryClass::Held));
        app.replace_composer_buffer("unsubmitted draft");

        app.queue_action_edit(None);

        assert_eq!(app.composer.text(), "unsubmitted draft");
        assert_eq!(app.queue.len(), 2);
    }

    #[test]
    fn authoritative_edit_rejection_discards_duplicate_composer_projection() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let first = item("editable draft", QueueDeliveryClass::Held);
        let first_id = first.id;
        app.queue.push(first);
        app.queue_action_edit(Some(first_id));
        app.pending_queue_edit_item_id = Some(first_id);
        let operation_id = Uuid::new_v4();
        app.pending_queue_edit_operation_id = Some(operation_id);
        app.pending_queue_edit_class = Some(QueueDeliveryClass::Held);

        app.apply_queue_control_response(
            cockpit_proto::Response::SetQueuedUserMessageClassResult {
                queue_item_id: first_id,
                applied: false,
                reason: cockpit_proto::RemoveQueuedUserMessageReason::AlreadyStarted,
                edit_operation_id: Some(operation_id),
                edit_action: Some(cockpit_proto::QueueEditAction::Reserve),
                item: None,
                queue: Vec::new(),
            },
        );

        assert!(app.composer.text().is_empty());
        assert!(app.pending_queue_edit_item_id.is_none());
        assert!(app.pending_queue_edit_class.is_none());
        assert!(!app.pending_queue_edit_reserved);
        assert!(!app.pending_queue_edit_commit);
    }

    #[test]
    fn expired_commit_lease_preserves_edited_draft_and_clears_edit_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let original = item("original queued text", QueueDeliveryClass::Held);
        let item_id = original.id;
        app.queue.push(original);
        let operation_id = Uuid::new_v4();
        app.pending_queue_edit_item_id = Some(item_id);
        app.pending_queue_edit_operation_id = Some(operation_id);
        app.pending_queue_edit_class = Some(QueueDeliveryClass::Held);
        app.pending_queue_edit_reserved = true;
        app.pending_queue_edit_commit = true;
        app.replace_composer_buffer("user's edited draft");
        let original_item = app.queue[0].clone();
        let original_queue = app.queue.clone();

        app.apply_queue_control_response(
            cockpit_proto::Response::SetQueuedUserMessageClassResult {
                queue_item_id: item_id,
                applied: false,
                reason: cockpit_proto::RemoveQueuedUserMessageReason::EditConflict,
                edit_operation_id: Some(operation_id),
                edit_action: Some(cockpit_proto::QueueEditAction::Commit),
                item: Some(original_item),
                queue: original_queue,
            },
        );

        assert_eq!(app.composer.text(), "user's edited draft");
        assert_eq!(app.queue.len(), 1);
        assert_eq!(app.queue[0].id, item_id);
        assert_eq!(app.queue[0].text, "original queued text");
        assert!(app.pending_queue_edit_item_id.is_none());
        assert!(app.pending_queue_edit_operation_id.is_none());
        assert!(app.pending_queue_edit_class.is_none());
        assert!(!app.pending_queue_edit_reserved);
        assert!(!app.pending_queue_edit_commit);
    }

    #[test]
    fn unrelated_edit_reply_cannot_advance_the_active_reservation() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let active_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        app.pending_queue_edit_item_id = Some(active_id);
        app.pending_queue_edit_operation_id = Some(operation_id);

        app.apply_queue_control_response(
            cockpit_proto::Response::SetQueuedUserMessageClassResult {
                queue_item_id: Uuid::new_v4(),
                applied: true,
                reason: cockpit_proto::RemoveQueuedUserMessageReason::Removed,
                edit_operation_id: Some(Uuid::new_v4()),
                edit_action: Some(cockpit_proto::QueueEditAction::Reserve),
                item: None,
                queue: Vec::new(),
            },
        );

        assert!(!app.pending_queue_edit_reserved);
        assert_eq!(app.pending_queue_edit_item_id, Some(active_id));
        assert_eq!(app.pending_queue_edit_operation_id, Some(operation_id));
    }

    #[test]
    fn ambiguous_edit_failure_keeps_identity_and_composer_fenced() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let item_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        app.pending_queue_edit_item_id = Some(item_id);
        app.pending_queue_edit_operation_id = Some(operation_id);
        app.pending_queue_edit_reserved = true;
        app.replace_composer_buffer("edited text");

        app.fail_pending_queue_edit("reply lost");

        assert_eq!(app.pending_queue_edit_item_id, Some(item_id));
        assert_eq!(app.pending_queue_edit_operation_id, Some(operation_id));
        assert!(app.pending_queue_edit_reserved);
        assert_eq!(app.composer.text(), "edited text");
    }

    #[test]
    fn stale_control_snapshot_cannot_resurrect_or_replace_event_owned_queue() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let current = item("current", QueueDeliveryClass::Steering);
        let stale = item("stale", QueueDeliveryClass::Held);
        app.reconcile_queue_update(vec![current.clone()]);

        app.apply_queue_control_response(
            cockpit_proto::Response::PromoteQueuedUserMessagesResult {
                applied: true,
                reason: cockpit_proto::RemoveQueuedUserMessageReason::Removed,
                queue: vec![stale],
            },
        );

        assert_eq!(app.queue.len(), 1);
        assert_eq!(app.queue[0].id, current.id);
    }

    #[test]
    fn keyboard_actions_require_queue_focus() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let first = item("one", QueueDeliveryClass::Steering);
        app.queue.push(first);
        let key = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE);
        assert!(!app.handle_queue_key(key));
        assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Steering);
        app.focus_queue_from_composer();
        assert!(app.handle_queue_key(key));
        let mut queue = app.queue.clone();
        queue[0].delivery_class = QueueDeliveryClass::Held;
        apply_snapshot(&mut app, queue);
        assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Held);
    }

    #[test]
    fn keyboard_shift_toggle_applies_to_all_messages() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.queue.push(item("held", QueueDeliveryClass::Held));
        app.queue.push(item("steer", QueueDeliveryClass::Steering));
        app.focus_queue_from_composer();

        assert!(app.handle_queue_key(KeyEvent::new(KeyCode::Char('T'), KeyModifiers::SHIFT)));

        let mut queue = app.queue.clone();
        for item in &mut queue {
            item.delivery_class = QueueDeliveryClass::Steering;
        }
        apply_snapshot(&mut app, queue);
        assert!(
            app.queue
                .iter()
                .all(|item| item.delivery_class == QueueDeliveryClass::Steering)
        );
    }

    #[test]
    fn keyboard_shift_cancel_removes_all_editable_messages() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.queue.push(item("one", QueueDeliveryClass::Steering));
        app.queue.push(item("two", QueueDeliveryClass::Held));
        app.focus_queue_from_composer();

        assert!(app.handle_queue_key(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::SHIFT)));

        apply_snapshot(&mut app, Vec::new());
        assert!(app.queue.is_empty());
    }

    #[test]
    fn keyboard_shift_send_now_dispatches_box_level_action() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.queue.push(item("queued", QueueDeliveryClass::Steering));
        app.focus_queue_from_composer();

        assert!(app.handle_queue_key(KeyEvent::new(KeyCode::Char('S'), KeyModifiers::SHIFT)));
        assert_eq!(app.queue.len(), 1);
    }

    #[test]
    fn mouse_dispatch_toggles_and_cancels() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let first = item("one", QueueDeliveryClass::Steering);
        let second = item("two", QueueDeliveryClass::Steering);
        let first_id = first.id;
        app.queue.extend([first, second]);
        app.dispatch_button(crate::tui::button::ButtonDispatch::QueueToggleClass {
            item_id: Some(first_id),
        });
        let mut queue = app.queue.clone();
        queue[0].delivery_class = QueueDeliveryClass::Held;
        apply_snapshot(&mut app, queue);
        assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Held);
        app.dispatch_button(crate::tui::button::ButtonDispatch::QueueCancel {
            item_id: Some(first_id),
        });
        let queue = app
            .queue
            .iter()
            .filter(|item| item.id != first_id)
            .cloned()
            .collect();
        apply_snapshot(&mut app, queue);
        assert_eq!(app.queue.len(), 1);
        assert_eq!(app.queue[0].text, "two");
    }

    #[test]
    fn setting_off_empty_enter_promotes_held_queue() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.config_snapshot.extended.queued_messages_as_steering = false;
        app.queue.push(item("held", QueueDeliveryClass::Held));
        app.queue_promote_all(QueueDeliveryClass::Steering);
        let mut queue = app.queue.clone();
        queue[0].delivery_class = QueueDeliveryClass::Steering;
        apply_snapshot(&mut app, queue);
        assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Steering);
    }

    #[test]
    fn hover_reveal_tracks_focus_and_hover() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let first = item("one", QueueDeliveryClass::Steering);
        let id = first.id;
        app.queue.push(first);
        assert!(!app.queue_message_revealed(id));
        app.queue_hover = Some(id);
        assert!(app.queue_message_revealed(id));
        app.queue_hover = None;
        app.queue_focus = Some(id);
        assert!(app.queue_message_revealed(id));
    }
}
