//! Conversation-rules review panel (`/rules`).
//!
//! Shows lineage-scoped advisory directives with attribution, a revoke
//! control, and a promote-to-instructions-file action. Distinct from `/pins`.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use cockpit_proto::ConversationRule;

use crate::tui::composer::display_width;

pub const RULES_YELLOW: Color = Color::Yellow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesReview {
    pub rules: Vec<ConversationRule>,
    pub cursor: usize,
}

impl RulesReview {
    pub fn enter(rules: Vec<ConversationRule>) -> Option<Self> {
        if rules.is_empty() {
            return None;
        }
        Some(Self { rules, cursor: 0 })
    }

    pub fn up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn down(&mut self) {
        if self.cursor + 1 < self.rules.len() {
            self.cursor += 1;
        }
    }

    pub fn selected(&self) -> Option<&ConversationRule> {
        self.rules.get(self.cursor)
    }

    pub fn remove_id(&mut self, rule_id: uuid::Uuid) -> bool {
        self.rules.retain(|rule| rule.rule_id != rule_id);
        if self.rules.is_empty() {
            return true;
        }
        if self.cursor >= self.rules.len() {
            self.cursor = self.rules.len() - 1;
        }
        false
    }

    pub fn render_lines(&self, width: u16) -> Vec<Line<'static>> {
        let mut out: Vec<Line<'static>> = Vec::new();
        out.push(Line::from(vec![Span::styled(
            format!(
                " Conversation rules ({}) — ↑/↓ · d revoke · p promote · esc close ",
                self.rules.len()
            ),
            Style::default()
                .fg(RULES_YELLOW)
                .add_modifier(Modifier::BOLD),
        )]));
        for (i, rule) in self.rules.iter().enumerate() {
            let who = match rule.created_by {
                cockpit_proto::ConversationRuleCreatedBy::User => "you",
                cockpit_proto::ConversationRuleCreatedBy::Agent => "agent",
            };
            let trust = rule.source_trust.as_str();
            let preview = preview_text(&rule.text, width.saturating_sub(18) as usize);
            let row = format!(" [ ] {who}/{trust} {preview}");
            let style = if i == self.cursor {
                Style::default()
                    .fg(RULES_YELLOW)
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED)
            } else {
                Style::default()
            };
            out.push(Line::from(Span::styled(row, style)));
        }
        out
    }
}

fn preview_text(text: &str, width: usize) -> String {
    let first = text.lines().next().unwrap_or("").trim();
    if display_width(first) <= width {
        return first.to_string();
    }
    let ellipsis = "…";
    let budget = width.saturating_sub(display_width(ellipsis));
    let mut prefix = String::new();
    for ch in first.chars() {
        let next = format!("{prefix}{ch}");
        if display_width(&next) > budget {
            break;
        }
        prefix = next;
    }
    prefix.push('…');
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_proto::{ConversationRuleCreatedBy, ConversationRuleSourceTrust};
    use uuid::Uuid;

    fn rule(text: &str, by: ConversationRuleCreatedBy) -> ConversationRule {
        ConversationRule {
            rule_id: Uuid::nil(),
            lineage_id: Uuid::nil(),
            text: text.to_string(),
            created_by: by,
            source_trust: ConversationRuleSourceTrust::Trusted,
            created_at_unix_ms: 1,
        }
    }

    #[test]
    fn navigation_and_remove() {
        let mut a = rule("prefer pnpm", ConversationRuleCreatedBy::Agent);
        a.rule_id = Uuid::from_u128(1);
        let mut b = rule("never touch prod", ConversationRuleCreatedBy::User);
        b.rule_id = Uuid::from_u128(2);
        let mut review = RulesReview::enter(vec![a, b]).unwrap();
        assert_eq!(review.selected().unwrap().text, "prefer pnpm");
        review.down();
        assert_eq!(review.selected().unwrap().text, "never touch prod");
        assert!(!review.remove_id(Uuid::from_u128(2)));
        assert_eq!(review.rules.len(), 1);
        assert!(review.remove_id(Uuid::from_u128(1)));
    }
}
