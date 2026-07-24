/// Horizontal bar gauge for a 0..100 percentage. `█` for the filled
/// portion, `░` for the rest. Rounds to the nearest cell and clamps into
/// `[0, width]`.
pub(crate) fn render_bar(pct: f64, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let frac = (pct / 100.0).clamp(0.0, 1.0);
    let filled = (frac * width as f64).round() as usize;
    let filled = filled.min(width);
    let mut s = String::with_capacity(width);
    s.push_str(&"█".repeat(filled));
    s.push_str(&"░".repeat(width - filled));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_bar_clamps_and_rounds() {
        assert_eq!(render_bar(0.0, 10), "░".repeat(10));
        assert_eq!(render_bar(100.0, 10), "█".repeat(10));
        let half = render_bar(50.0, 10);
        assert_eq!(half.chars().filter(|c| *c == '█').count(), 5);
        assert_eq!(half.chars().count(), 10);
        assert_eq!(render_bar(250.0, 8), "█".repeat(8));
        assert_eq!(render_bar(-5.0, 8), "░".repeat(8));
        assert_eq!(render_bar(50.0, 0), "");
    }
}
