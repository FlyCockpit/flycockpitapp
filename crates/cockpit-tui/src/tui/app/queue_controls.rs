//! Queue-box controls: class toggles, send-now, edit, cancel, and focus.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use uuid::Uuid;

use super::App;
use cockpit_proto::{QueueDeliveryClass, Request};

impl App {
    pub(super) fn queue_visual_ids(&self) -> Vec<Uuid> {
        let (steering, held) = self.queue_grouped();
        steering
            .into_iter()
            .chain(held)
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
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return false;
        }
        match key.code {
            KeyCode::Esc => {
                self.blur_queue_focus();
                true
            }
            KeyCode::Up => {
                let _ = self.queue_focus_move(-1);
                true
            }
            KeyCode::Down => {
                if !self.queue_focus_move(1) {
                    self.blur_queue_focus();
                }
                true
            }
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
            KeyCode::Char('x') | KeyCode::Delete | KeyCode::Backspace => {
                if let Some(id) = self.queue_focus {
                    self.queue_action_cancel(Some(id));
                }
                true
            }
            _ => true,
        }
    }

    pub(super) fn queue_action_send_now(&mut self, item_id: Option<Uuid>) {
        let ids: Vec<Uuid> = match item_id {
            Some(id) => vec![id],
            None => self.queue.iter().map(|item| item.id).collect(),
        };
        for id in ids {
            self.send_queue_request(Request::SendNowQueuedUserMessage { queue_item_id: id });
        }
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
                });
                if let Some(item) = self.queue.iter_mut().find(|item| item.id == id) {
                    item.delivery_class = delivery_class;
                }
            }
            None => {
                let delivery_class = if self.queue_has_held() {
                    QueueDeliveryClass::Steering
                } else {
                    QueueDeliveryClass::Held
                };
                self.queue_promote_all(delivery_class);
            }
        }
    }

    pub(super) fn queue_promote_all(&mut self, delivery_class: QueueDeliveryClass) {
        for item in &mut self.queue {
            item.delivery_class = delivery_class;
        }
        self.send_queue_request(Request::PromoteQueuedUserMessages { delivery_class });
    }

    pub(super) fn queue_action_edit(&mut self, item_id: Option<Uuid>) {
        match item_id {
            Some(id) => self.edit_one_queued_message(id),
            None => {
                let _ = self.edit_queued_messages();
            }
        }
    }

    pub(super) fn queue_action_cancel(&mut self, item_id: Option<Uuid>) {
        match item_id {
            Some(id) => {
                self.queue.retain(|item| item.id != id);
                if self.queue_focus == Some(id) {
                    self.queue_focus = self.queue_visual_ids().last().copied();
                }
                self.send_queue_request(Request::RemoveQueuedUserMessage { queue_item_id: id });
            }
            None => {
                self.queue.clear();
                self.queue_focus = None;
                self.send_queue_request(Request::RemoveEditableQueuedUserMessages {
                    target_id: None,
                });
            }
        }
    }

    fn edit_one_queued_message(&mut self, id: Uuid) {
        let Some(index) = self.queue.iter().position(|item| item.id == id) else {
            return;
        };
        let item = self.queue.remove(index);
        self.pending_queue_edit_class = Some(item.delivery_class);
        let text = item
            .display_text
            .filter(|value| !value.is_empty())
            .unwrap_or(item.text);
        self.replace_composer_buffer(text);
        self.blur_queue_focus();
        self.send_queue_request(Request::RemoveQueuedUserMessage { queue_item_id: id });
    }

    fn send_queue_request(&mut self, request: Request) {
        let Some(attached) = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .map(|runner| runner.attached_request_binding())
        else {
            return;
        };
        self.async_actions.start_serialized(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("queue.control"),
            crate::tui::async_action::AsyncActionKey::new("queue.control"),
            async move {
                attached.request(request).await.map(|response| {
                    crate::tui::async_action::AsyncActionPayload::DaemonResponse(Box::new(response))
                })
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
        match response {
            cockpit_proto::Response::SetQueuedUserMessageClassResult { queue, .. }
            | cockpit_proto::Response::PromoteQueuedUserMessagesResult { queue, .. }
            | cockpit_proto::Response::SendNowQueuedUserMessageResult { queue, .. }
            | cockpit_proto::Response::RemoveQueuedUserMessageResult { queue, .. }
            | cockpit_proto::Response::RemoveQueuedUserMessagesResult { queue, .. } => {
                self.replace_queue_from_proto(queue);
            }
            _ => {}
        }
        if let Some(id) = self.queue_focus
            && !self.queue.iter().any(|item| item.id == id)
        {
            self.queue_focus = self.queue_visual_ids().last().copied();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_proto::{QueueItemStatus, QueueTarget};

    fn item(text: &str, class: QueueDeliveryClass) -> cockpit_proto::QueueItem {
        cockpit_proto::QueueItem {
            id: Uuid::new_v4(),
            status: QueueItemStatus::Queued,
            text: text.to_string(),
            display_text: None,
            target: QueueTarget::root("Build"),
            delivery_class: class,
        }
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
        assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Held);
        assert_eq!(app.queue[1].delivery_class, QueueDeliveryClass::Steering);
        app.queue_action_cancel(Some(first_id));
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
        assert!(
            app.queue
                .iter()
                .all(|item| item.delivery_class == QueueDeliveryClass::Steering)
        );
        assert_eq!(app.queue_box_toggle_label(), "hold all");
    }

    #[test]
    fn edit_one_preserves_remaining_order_and_stashes_class() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let first = item("one", QueueDeliveryClass::Steering);
        let second = item("two", QueueDeliveryClass::Held);
        let first_id = first.id;
        app.queue.extend([first, second]);
        app.queue_action_edit(Some(first_id));
        assert_eq!(app.composer.text(), "one");
        assert_eq!(app.queue.len(), 1);
        assert_eq!(app.queue[0].text, "two");
        assert_eq!(
            app.pending_queue_edit_class,
            Some(QueueDeliveryClass::Steering)
        );
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
        assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Held);
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
        assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Held);
        app.dispatch_button(crate::tui::button::ButtonDispatch::QueueCancel {
            item_id: Some(first_id),
        });
        assert_eq!(app.queue.len(), 1);
        assert_eq!(app.queue[0].text, "two");
    }

    #[test]
    fn setting_off_empty_enter_promotes_held_queue() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.extended.queued_messages_as_steering = false;
        app.queue.push(item("held", QueueDeliveryClass::Held));
        app.queue_promote_all(QueueDeliveryClass::Steering);
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
