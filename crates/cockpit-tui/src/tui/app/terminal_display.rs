use super::*;

impl App {
    /// Push the right cursor shape to the terminal based on vim mode.
    /// Idempotent — only writes when the desired shape changes.
    pub(super) fn sync_cursor_shape(&mut self) {
        let desired = if self.composer.vim_enabled()
            && !matches!(self.composer.vim_mode(), VimMode::Insert)
        {
            CursorShape::Block
        } else {
            CursorShape::Bar
        };
        if self.last_cursor_shape == Some(desired) {
            return;
        }
        let style = match desired {
            CursorShape::Block => SetCursorStyle::SteadyBlock,
            CursorShape::Bar => SetCursorStyle::SteadyBar,
        };
        let _ = crossterm::execute!(stdout(), style);
        self.last_cursor_shape = Some(desired);
    }
}
