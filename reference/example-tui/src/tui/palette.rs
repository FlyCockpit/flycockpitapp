//! The warm instrument-panel palette, kept in step with the onboarding
//! wizard's [`crate::onboard::agent::ui`] colours on purpose so the two TUIs
//! read as one product. Status dots follow the web console's red/yellow/green
//! convention: yellow = working, red = waiting on you, green = done.

use ratatui::style::Color;

/// Bright foreground text.
pub const INK: Color = Color::Rgb(0xF4, 0xEF, 0xE6);
/// Muted secondary text.
pub const FOG: Color = Color::Rgb(0x8A, 0x9B, 0xB0);
/// The accent — selection, the primary action, the caret.
pub const BRASS: Color = Color::Rgb(0xE0, 0xB1, 0x56);
/// Borders and rules at rest.
pub const NIGHT: Color = Color::Rgb(0x4A, 0x5A, 0x6A);
/// Dimmest text: disabled labels, reasoning traces.
pub const DISABLED: Color = Color::Rgb(0x55, 0x62, 0x70);
/// The wash behind a hovered or focused row.
pub const HOVER_BG: Color = Color::Rgb(0x2C, 0x38, 0x46);
/// A slightly lifted surface for cards and the sticky header.
pub const SURFACE: Color = Color::Rgb(0x1C, 0x26, 0x30);
/// Italic placeholder text in empty fields.
pub const PLACEHOLDER: Color = Color::Rgb(0x6A, 0x7A, 0x8A);

/// Working — a turn is in flight.
pub const YELLOW: Color = Color::Rgb(0xE0, 0xB1, 0x56);
/// Waiting on you — the run is parked on your answer.
pub const RED: Color = Color::Rgb(0xD9, 0x6A, 0x6A);
/// Done / clear.
pub const GREEN: Color = Color::Rgb(0x7F, 0xC9, 0x8A);
/// Interactive subagent gutter — distinct from the brass user-message bar.
pub const TEAL: Color = Color::Rgb(0x4E, 0xC8, 0xC4);
