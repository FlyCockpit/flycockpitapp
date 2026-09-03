//! Conversation-rules TUI integration: `/rules` panel, `/rule` create,
//! revoke, and promote-to-instructions-file.

use super::App;
use crate::tui::async_action::{
    AsyncActionKey, AsyncActionKind, AsyncActionPayload, AsyncActionPolicy,
};
use crate::tui::rules_overlay::RulesReview;

impl App {
    pub(super) fn enter_rules_review_mode(&mut self) {
        if self.any_overlay_open() {
            return;
        }
        let Some(sid) = self.current_session_id() else {
            self.push_plain("/rules: no active session".to_string());
            return;
        };
        let Some(socket) = self.pins_socket() else {
            return;
        };
        self.async_actions.start_blocking(
            AsyncActionKind::Internal("rules.review"),
            AsyncActionPolicy::Replace(AsyncActionKey::new(format!("rules.review:{sid}"))),
            move || {
                let rules = match pin_rpc(
                    &socket,
                    cockpit_proto::Request::ListConversationRules { session_id: sid },
                )? {
                    cockpit_proto::Response::ConversationRules { rules } => rules,
                    other => return Err(format!("unexpected rules-review response: {other:?}")),
                };
                Ok(AsyncActionPayload::RulesReview {
                    session_id: sid,
                    rules,
                })
            },
        );
    }

    pub(super) fn apply_rules_review(
        &mut self,
        sid: uuid::Uuid,
        rules: Vec<cockpit_proto::ConversationRule>,
    ) {
        if self.current_session_id() != Some(sid) {
            return;
        }
        match RulesReview::enter(rules) {
            Some(review) => {
                self.pin_pick = None;
                self.fork_pick = None;
                self.copy_pick = None;
                self.pins_review = None;
                self.rules_review = Some(review);
            }
            None => self.push_plain("/rules: no conversation rules".to_string()),
        }
    }

    pub(super) fn handle_rule_command(&mut self, args: &str) {
        let text = args.trim();
        if text.is_empty() {
            self.enter_rules_review_mode();
            return;
        }
        let Some(sid) = self.current_session_id() else {
            self.push_plain("/rule: no active session".to_string());
            return;
        };
        let Some(socket) = self.pins_socket() else {
            return;
        };
        let text = text.to_string();
        self.async_actions.start_blocking(
            AsyncActionKind::Internal("rules.set"),
            AsyncActionPolicy::Replace(AsyncActionKey::new(format!("rules.set:{sid}"))),
            move || match pin_rpc(
                &socket,
                cockpit_proto::Request::SetConversationRule {
                    session_id: sid,
                    rule_id: None,
                    text,
                    source_trust: Some("trusted".into()),
                },
            )? {
                cockpit_proto::Response::ConversationRuleChanged { rule } => {
                    Ok(AsyncActionPayload::RuleSet { rule })
                }
                other => Err(format!("unexpected set-rule response: {other:?}")),
            },
        );
    }

    pub(super) fn rules_review_up(&mut self) {
        if let Some(review) = self.rules_review.as_mut() {
            review.up();
        }
    }

    pub(super) fn rules_review_down(&mut self) {
        if let Some(review) = self.rules_review.as_mut() {
            review.down();
        }
    }

    pub(super) fn rules_review_revoke_selected(&mut self) {
        let Some(sid) = self.current_session_id() else {
            return;
        };
        let Some(rule_id) = self
            .rules_review
            .as_ref()
            .and_then(|review| review.selected())
            .map(|rule| rule.rule_id)
        else {
            return;
        };
        let Some(socket) = self.pins_socket() else {
            return;
        };
        self.async_actions.start_blocking(
            AsyncActionKind::Internal("rules.remove"),
            AsyncActionPolicy::Replace(AsyncActionKey::new(format!("rules.remove:{sid}"))),
            move || match pin_rpc(
                &socket,
                cockpit_proto::Request::RemoveConversationRule {
                    session_id: sid,
                    rule_id,
                },
            )? {
                cockpit_proto::Response::ConversationRuleRemoved { removed } => {
                    Ok(AsyncActionPayload::RuleRemoved { rule_id, removed })
                }
                other => Err(format!("unexpected remove-rule response: {other:?}")),
            },
        );
    }

    pub(super) fn apply_rule_removed(&mut self, rule_id: uuid::Uuid, removed: bool) {
        if !removed {
            self.push_plain("/rules: rule already revoked".to_string());
            return;
        }
        if let Some(review) = self.rules_review.as_mut()
            && review.remove_id(rule_id)
        {
            self.rules_review = None;
        }
        self.push_plain("/rules: revoked".to_string());
    }

    pub(super) fn apply_rule_set(&mut self, rule: cockpit_proto::ConversationRule) {
        self.push_plain(format!("/rule: saved `{}`", rule.rule_id));
        if let Some(review) = self.rules_review.as_mut() {
            if let Some(existing) = review
                .rules
                .iter_mut()
                .find(|row| row.rule_id == rule.rule_id)
            {
                *existing = rule;
            } else {
                review.rules.push(rule);
            }
        }
    }

    pub(super) fn rules_review_promote_selected(&mut self) {
        let Some(sid) = self.current_session_id() else {
            return;
        };
        let Some(rule_id) = self
            .rules_review
            .as_ref()
            .and_then(|review| review.selected())
            .map(|rule| rule.rule_id)
        else {
            return;
        };
        let Some(socket) = self.pins_socket() else {
            return;
        };
        self.async_actions.start_blocking(
            AsyncActionKind::Internal("rules.promote"),
            AsyncActionPolicy::Replace(AsyncActionKey::new(format!("rules.promote:{sid}"))),
            move || match pin_rpc(
                &socket,
                cockpit_proto::Request::PromoteConversationRule {
                    session_id: sid,
                    rule_id,
                },
            )? {
                cockpit_proto::Response::ConversationRulePromoted {
                    target_path,
                    report,
                    ..
                } => Ok(AsyncActionPayload::RulePromoted {
                    target_path,
                    report,
                }),
                other => Err(format!("unexpected promote-rule response: {other:?}")),
            },
        );
    }

    pub(super) fn apply_rule_promoted(&mut self, target_path: String, report: String) {
        self.push_plain(format!("/rules: promoted into {target_path}"));
        if !report.trim().is_empty() {
            self.push_plain(report);
        }
    }

    pub(super) fn close_rules_review(&mut self) {
        self.rules_review = None;
    }
}

fn pin_rpc(
    endpoint: &cockpit_client::ClientEndpoint,
    request: cockpit_proto::Request,
) -> Result<cockpit_proto::Response, String> {
    crate::tui::agent_runner::daemon_request_at_blocking(endpoint, request)
}
