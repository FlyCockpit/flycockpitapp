use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::Rect;

use super::dispatch::{ButtonDispatch, ButtonPointerOutcome, RowDispatch};
use super::id::{ButtonId, ButtonSpec};
use super::paint::paint_button;
use super::{RowControlId, button_style};

#[derive(Debug, Clone)]
pub(crate) struct RegisteredButton {
    pub id: ButtonId,
    pub rect: Rect,
    pub enabled: bool,
    pub dispatch: ButtonDispatch,
    pub generation: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct ButtonPress {
    /// Identity is the `ButtonId`. A redraw of the same id on the same
    /// surface (a new per-frame generation) must not cancel the press.
    pub id: ButtonId,
}

#[derive(Debug, Default)]
pub(crate) struct ButtonRegistry {
    generation: u64,
    surface_generation: u64,
    capture: bool,
    hover: Option<ButtonId>,
    pressed: Option<ButtonPress>,
    targets: Vec<RegisteredButton>,
    last_activated: Option<ButtonId>,
}

impl ButtonRegistry {
    pub fn begin_frame(&mut self, capture: bool, surface_generation: u64) {
        if self.surface_generation != surface_generation {
            self.hover = None;
            self.pressed = None;
            self.last_activated = None;
        }
        self.surface_generation = surface_generation;
        self.generation = self.generation.wrapping_add(1);
        self.targets.clear();
        self.last_activated = None;
        self.capture = capture;
        if !capture {
            self.hover = None;
            self.pressed = None;
        }
        let _ = super::button_inventory().len();
    }

    pub fn end_frame(&mut self) {
        if let Some(id) = &self.hover
            && !self.targets.iter().any(|target| target.id == *id)
        {
            self.hover = None;
        }
        if let Some(press) = &self.pressed
            && !self
                .targets
                .iter()
                .any(|target| target.id == press.id && target.enabled)
        {
            self.pressed = None;
        }
    }

    pub fn capture(&self) -> bool {
        self.capture
    }

    pub fn hover(&self) -> Option<&ButtonId> {
        self.hover.as_ref()
    }

    pub fn pressed(&self) -> Option<&ButtonPress> {
        self.pressed.as_ref()
    }

    pub fn targets(&self) -> &[RegisteredButton] {
        &self.targets
    }

    pub fn clear_hover_and_pressed(&mut self) {
        self.hover = None;
        self.pressed = None;
    }

    pub fn paint(
        &mut self,
        frame: &mut Frame<'_>,
        x: u16,
        y: u16,
        max_width: u16,
        spec: ButtonSpec,
    ) -> Option<Rect> {
        let hover = self.hover.as_ref() == Some(&spec.id);
        let pressed = self
            .pressed
            .as_ref()
            .is_some_and(|press| press.id == spec.id);
        let style = button_style(&spec, hover, pressed);
        let rect = paint_button(frame, x, y, max_width, &spec, style)?;
        if self.capture {
            self.targets.push(RegisteredButton {
                id: spec.id,
                rect,
                enabled: spec.enabled,
                dispatch: spec.dispatch,
                generation: self.generation,
            });
        }
        Some(rect)
    }

    pub fn hit(&self, column: u16, row: u16) -> Option<&RegisteredButton> {
        if !self.capture {
            return None;
        }
        self.targets.iter().rev().find(|target| {
            column >= target.rect.x
                && column < target.rect.right()
                && row >= target.rect.y
                && row < target.rect.bottom()
        })
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<ButtonPointerOutcome> {
        match mouse.kind {
            MouseEventKind::Moved => {
                let next = self
                    .hit(mouse.column, mouse.row)
                    .filter(|target| target.enabled)
                    .map(|target| target.id.clone());
                if self.hover != next {
                    self.hover = next.clone();
                    if let Some(press) = &self.pressed
                        && self.hover.as_ref() != Some(&press.id)
                    {
                        self.pressed = None;
                        return Some(ButtonPointerOutcome::Cancelled);
                    }
                    return next.map(|_| ButtonPointerOutcome::HoverChanged);
                }
                if let Some(press) = &self.pressed
                    && self.hover.as_ref() != Some(&press.id)
                {
                    self.pressed = None;
                    return Some(ButtonPointerOutcome::Cancelled);
                }
                next.map(|_| ButtonPointerOutcome::Consumed)
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let Some(target) = self.hit(mouse.column, mouse.row).cloned() else {
                    if self.pressed.take().is_some() {
                        return Some(ButtonPointerOutcome::Cancelled);
                    }
                    return None;
                };
                if !target.enabled {
                    self.pressed = None;
                    return Some(ButtonPointerOutcome::Consumed);
                }
                self.hover = Some(target.id.clone());
                self.pressed = Some(ButtonPress {
                    id: target.id.clone(),
                });
                Some(ButtonPointerOutcome::Pressed(target.id))
            }
            MouseEventKind::Up(MouseButton::Left) => {
                let Some(press) = self.pressed.take() else {
                    return None;
                };
                let Some(target) = self.hit(mouse.column, mouse.row).cloned() else {
                    return Some(ButtonPointerOutcome::Cancelled);
                };
                if !target.enabled || target.id != press.id {
                    return Some(ButtonPointerOutcome::Cancelled);
                }
                if self.last_activated.as_ref() == Some(&target.id)
                    && !dispatch_is_idempotent(&target.dispatch)
                {
                    return Some(ButtonPointerOutcome::Consumed);
                }
                self.last_activated = Some(target.id.clone());
                Some(ButtonPointerOutcome::Activated(target.dispatch))
            }
            MouseEventKind::Down(_) => {
                if self.pressed.take().is_some() {
                    Some(ButtonPointerOutcome::Cancelled)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

fn dispatch_is_idempotent(dispatch: &ButtonDispatch) -> bool {
    matches!(
        dispatch,
        ButtonDispatch::Footer(_)
            | ButtonDispatch::TranscriptPin { .. }
            | ButtonDispatch::TranscriptUnpin { .. }
            | ButtonDispatch::TranscriptFork { .. }
            | ButtonDispatch::PersistentNoticeCopy
    )
}

#[derive(Debug, Clone)]
pub(crate) struct RowTarget {
    pub id: RowControlId,
    pub rect: Rect,
    pub dispatch: RowDispatch,
}

#[derive(Debug, Default)]
pub(crate) struct RowControlRegistry {
    capture: bool,
    targets: Vec<RowTarget>,
}

impl RowControlRegistry {
    pub fn begin_frame(&mut self, capture: bool) {
        self.targets.clear();
        self.capture = capture;
    }

    pub fn register(&mut self, target: RowTarget) {
        if self.capture {
            self.targets.push(target);
        }
    }

    pub fn targets(&self) -> &[RowTarget] {
        &self.targets
    }

    pub fn hit(&self, column: u16, row: u16) -> Option<&RowTarget> {
        if !self.capture {
            return None;
        }
        self.targets.iter().rev().find(|target| {
            column >= target.rect.x
                && column < target.rect.right()
                && row >= target.rect.y
                && row < target.rect.bottom()
        })
    }
}
