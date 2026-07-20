use std::io::{self, IsTerminal, Write};

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRegion {
    pub rect: Rect,
    pub url: String,
    pub label: String,
}

#[derive(Debug, Default)]
pub struct LinkRegistry {
    regions: Vec<LinkRegion>,
    hovered: Option<usize>,
    hovered_url: Option<String>,
}

impl LinkRegistry {
    pub fn begin_frame(&mut self) {
        self.regions.clear();
        self.hovered = None;
    }

    pub fn register(&mut self, rect: Rect, url: impl Into<String>, label: impl Into<String>) {
        if rect.width > 0 && rect.height == 1 {
            let url = url.into();
            let index = self.regions.len();
            if self.hovered_url.as_deref() == Some(url.as_str()) {
                self.hovered = Some(index);
            }
            self.regions.push(LinkRegion {
                rect,
                url,
                label: label.into(),
            });
        }
    }

    pub fn at(&self, col: u16, row: u16) -> Option<&LinkRegion> {
        self.regions.iter().find(|link| {
            col >= link.rect.x
                && col < link.rect.x.saturating_add(link.rect.width)
                && row == link.rect.y
        })
    }

    pub fn update_hover(&mut self, col: u16, row: u16) -> bool {
        let next = self.regions.iter().position(|link| {
            col >= link.rect.x
                && col < link.rect.x.saturating_add(link.rect.width)
                && row == link.rect.y
        });
        let changed = next != self.hovered;
        self.hovered = next;
        self.hovered_url = next.map(|index| self.regions[index].url.clone());
        changed
    }

    pub fn clear_hover(&mut self) {
        self.hovered = None;
        self.hovered_url = None;
    }

    pub fn hovered(&self) -> Option<&LinkRegion> {
        self.hovered.and_then(|index| self.regions.get(index))
    }

    pub fn hovered_url(&self) -> Option<&str> {
        self.hovered_url.as_deref()
    }

    pub fn regions(&self) -> &[LinkRegion] {
        &self.regions
    }
}

pub fn base_link_style() -> Style {
    Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::UNDERLINED)
}

pub fn hovered_link_style() -> Style {
    base_link_style().add_modifier(Modifier::BOLD)
}

pub fn link_style(hovered: bool) -> Style {
    if hovered {
        hovered_link_style()
    } else {
        base_link_style()
    }
}

pub fn clipped_label(label: &str, width: u16) -> String {
    let width = usize::from(width);
    if width == 0 {
        return String::new();
    }
    if UnicodeWidthStr::width(label) <= width {
        return label.to_string();
    }
    if width == 1 {
        return "…".into();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in label.chars() {
        let ch_width = ch.width().unwrap_or(0);
        if used + ch_width > width - 1 {
            break;
        }
        out.push(ch);
        used += ch_width;
    }
    out.push('…');
    out
}

fn safe_url(url: &str) -> bool {
    !url.is_empty() && !url.chars().any(char::is_control)
}

pub fn osc8_bytes(registry: &LinkRegistry, enabled: bool, is_tty: bool) -> Vec<u8> {
    if !enabled || !is_tty {
        return Vec::new();
    }
    let links = registry
        .regions()
        .iter()
        .filter(|link| safe_url(&link.url))
        .collect::<Vec<_>>();
    if links.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"\x1b7");
    out.extend_from_slice(b"\x1b[?25l");
    for link in links {
        let sequence = format!(
            "\x1b[{};{}H\x1b]8;;{}\x1b\\\x1b[36;4m{}\x1b[0m\x1b]8;;\x1b\\",
            link.rect.y + 1,
            link.rect.x + 1,
            link.url,
            link.label
        );
        out.extend_from_slice(sequence.as_bytes());
    }
    out.extend_from_slice(b"\x1b[?25h");
    out.extend_from_slice(b"\x1b8");
    out
}

pub fn emit_osc8(registry: &LinkRegistry, enabled: bool) -> io::Result<()> {
    let stdout = io::stdout();
    let bytes = osc8_bytes(registry, enabled, stdout.is_terminal());
    if bytes.is_empty() {
        return Ok(());
    }
    let mut lock = stdout.lock();
    lock.write_all(&bytes)?;
    lock.flush()
}

pub fn open_browser(url: &str) -> anyhow::Result<()> {
    cockpit_core::browser::open(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipping_is_single_line_and_uses_ellipsis() {
        assert_eq!(clipped_label("abcdefgh", 5), "abcd…");
        assert_eq!(clipped_label("abcdefgh", 1), "…");
    }

    #[test]
    fn registry_rebuild_and_hit_test() {
        let mut links = LinkRegistry::default();
        links.register(Rect::new(2, 3, 4, 1), "https://x.test", "link");
        assert_eq!(links.regions().len(), 1);
        assert!(links.at(2, 3).is_some());
        assert!(links.at(6, 3).is_none());
        links.begin_frame();
        assert!(links.regions().is_empty());
    }

    #[test]
    fn hover_getter_and_styles_reflect_hovered_region() {
        let mut links = LinkRegistry::default();
        links.register(Rect::new(2, 3, 4, 1), "https://x.test", "link");
        assert!(links.hovered().is_none());
        assert!(links.update_hover(2, 3));
        assert_eq!(
            links.hovered().map(|link| link.url.as_str()),
            Some("https://x.test")
        );
        assert!(
            hovered_link_style()
                .add_modifier
                .contains(Modifier::UNDERLINED)
        );
        assert!(hovered_link_style().add_modifier.contains(Modifier::BOLD));
        assert!(!base_link_style().add_modifier.contains(Modifier::BOLD));
        assert!(links.update_hover(7, 3));
        assert!(links.hovered().is_none());
    }

    #[test]
    fn osc8_is_gated_rejects_control_characters_and_preserves_label() {
        let mut links = LinkRegistry::default();
        links.register(Rect::new(1, 2, 4, 1), "https://x.test", "painted");
        links.register(Rect::new(1, 3, 4, 1), "https://bad\n.test", "bad");
        assert!(osc8_bytes(&links, false, true).is_empty());
        assert!(osc8_bytes(&links, true, false).is_empty());
        let rendered = String::from_utf8(osc8_bytes(&links, true, true)).unwrap();
        assert!(rendered.contains("\x1b7\x1b[?25l"));
        assert!(rendered.contains("\x1b[36;4mpainted\x1b[0m"));
        assert!(rendered.contains("\x1b[?25h\x1b8"));
        assert!(!rendered.contains("bad"));
    }

    #[test]
    fn osc8_short_circuits_without_safe_links_and_ignores_hover() {
        let empty = LinkRegistry::default();
        assert!(osc8_bytes(&empty, true, true).is_empty());

        let mut links = LinkRegistry::default();
        links.register(Rect::new(1, 2, 4, 1), "https://bad\n.test", "bad");
        assert!(osc8_bytes(&links, true, true).is_empty());

        let mut links = LinkRegistry::default();
        links.register(Rect::new(1, 2, 4, 1), "https://x.test", "link");
        let before = osc8_bytes(&links, true, true);
        assert!(links.update_hover(1, 2));
        let after = osc8_bytes(&links, true, true);
        assert_eq!(before, after);
    }
}
