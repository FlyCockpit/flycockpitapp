//! Sealed `[label]` button primitive and interaction registry.
//!
//! Compact user-invokable TUI actions render only through
//! [`ButtonRegistry::paint`]. The painted `[label]` cells and the
//! pointer rectangle are the same measured result.

#![allow(dead_code)]

mod dispatch;
mod id;
mod inventory;
mod paint;
mod registry;

pub(crate) use dispatch::{ButtonDispatch, ButtonPointerOutcome, RowDispatch};
pub(crate) use id::{ButtonId, ButtonKind, ButtonSpec, RowControlId};
pub(crate) use inventory::button_inventory;
pub(crate) use paint::{bracketed_label, first_bracketed_label};
pub(crate) use registry::{ButtonRegistry, RowControlRegistry, RowTarget};

// Re-exports consumed only by the crate's `#[cfg(test)]` modules (button
// tests and settings pointer tests). Gated so the non-test lib build does not
// see them as unused imports.
#[cfg(test)]
pub(crate) use id::{ControlKind, OverlaySurface};
#[cfg(test)]
pub(crate) use inventory::{InventoryMember, settings_pointer_control_kind};
#[cfg(test)]
pub(crate) use paint::{clip_to_display_width, display_width};
#[cfg(test)]
pub(crate) use registry::RegisteredButton;

use ratatui::style::Style;

use crate::tui::theme::{
    button_destructive_style, button_disabled_style, button_focus_style, button_hover_style,
    button_idle_style, button_pressed_style,
};

#[cfg(test)]
mod tests;

pub(crate) fn button_style(spec: &ButtonSpec, hover: bool, pressed: bool) -> Style {
    if !spec.enabled {
        return button_disabled_style();
    }
    if pressed {
        return button_pressed_style();
    }
    if hover {
        return button_hover_style();
    }
    if spec.focused {
        return button_focus_style();
    }
    if spec.kind == ButtonKind::Destructive {
        return button_destructive_style();
    }
    button_idle_style()
}
