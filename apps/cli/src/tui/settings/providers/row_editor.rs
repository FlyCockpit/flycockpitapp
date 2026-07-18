use crossterm::event::{KeyCode, KeyEvent};

use crate::config::providers::{HeaderSpec, ModelEntry, apply_template_model_defaults};
use crate::tui::textfield::TextField;

use super::super::RowDeleteConfirm;

pub(in crate::tui::settings) trait RowListEditor {
    type Result;

    fn n_rows(&self) -> usize;
    fn cursor(&self) -> usize;
    fn set_cursor(&mut self, cursor: usize);
    fn is_browsing(&self) -> bool;
    fn delete(&mut self) -> &mut RowDeleteConfirm;
    fn status(&mut self) -> &mut Option<String>;
    fn delete_label(&self, index: usize) -> String;
    fn remove_row(&mut self, index: usize);
    fn save_idx(&self) -> Option<usize>;

    fn continue_idx(&self) -> Option<usize> {
        None
    }

    fn start_add(&mut self);
    fn start_edit(&mut self, index: usize);
    fn commit_edit_fields(&mut self) -> Result<(), String>;
    fn finish_edit(&mut self);
    fn cycle_edit_focus(&mut self, reverse: bool);
    fn handle_edit_input(&mut self, key: KeyEvent);

    fn stay_result() -> Self::Result;
    fn back_result() -> Self::Result;
    fn save_result() -> Self::Result;
    fn continue_result() -> Self::Result {
        Self::stay_result()
    }
    fn activate_row(&mut self, index: usize) -> Self::Result;

    fn add_row_idx(&self) -> usize {
        self.n_rows()
    }

    fn max_cursor(&self) -> usize {
        self.continue_idx()
            .or_else(|| self.save_idx())
            .unwrap_or(self.add_row_idx())
    }

    fn begin_add(&mut self) {
        self.delete().disarm();
        *self.status() = None;
        self.start_add();
    }

    fn begin_edit(&mut self, index: usize) {
        if index < self.n_rows() {
            self.delete().disarm();
            *self.status() = None;
            self.start_edit(index);
        }
    }

    fn commit_edit(&mut self) -> Result<(), String> {
        self.commit_edit_fields()?;
        self.finish_edit();
        self.delete().disarm();
        *self.status() = None;
        Ok(())
    }

    fn cancel_edit(&mut self) {
        self.finish_edit();
        self.delete().disarm();
        self.on_cancel_edit();
    }

    fn on_cancel_edit(&mut self) {}

    fn handle_save_shortcut(&mut self) -> Self::Result {
        Self::save_result()
    }

    fn handle_custom_browse_key(&mut self, _key: KeyEvent) -> Option<Self::Result> {
        None
    }

    fn handle_browse_key(&mut self, key: KeyEvent) -> Self::Result {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                let next = crate::tui::nav::wrap_prev(self.cursor(), self.max_cursor() + 1);
                self.set_cursor(next);
                self.delete().disarm();
                *self.status() = None;
                Self::stay_result()
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                let next = crate::tui::nav::wrap_next(self.cursor(), self.max_cursor() + 1);
                self.set_cursor(next);
                self.delete().disarm();
                *self.status() = None;
                Self::stay_result()
            }
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
                self.delete().disarm();
                Self::back_result()
            }
            KeyCode::Char('a') => {
                self.begin_add();
                Self::stay_result()
            }
            KeyCode::Char('s') if self.save_idx().is_some() => self.handle_save_shortcut(),
            KeyCode::Char('d') | KeyCode::Delete => self.handle_delete_key(),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => self.handle_activate_key(),
            _ => {
                if let Some(result) = self.handle_custom_browse_key(key) {
                    result
                } else {
                    self.delete().disarm();
                    *self.status() = None;
                    Self::stay_result()
                }
            }
        }
    }

    fn handle_edit_key(&mut self, key: KeyEvent) -> Self::Result {
        match key.code {
            KeyCode::Esc => {
                self.cancel_edit();
                Self::stay_result()
            }
            KeyCode::Enter => {
                if let Err(msg) = self.commit_edit() {
                    *self.status() = Some(msg);
                }
                Self::stay_result()
            }
            KeyCode::Tab => {
                self.cycle_edit_focus(false);
                Self::stay_result()
            }
            KeyCode::BackTab => {
                self.cycle_edit_focus(true);
                Self::stay_result()
            }
            _ => {
                self.handle_edit_input(key);
                Self::stay_result()
            }
        }
    }

    fn handle_delete_key(&mut self) -> Self::Result {
        let cursor = self.cursor();
        if cursor < self.n_rows() {
            let label = self.delete_label(cursor);
            if self.delete().arm_or_confirm(cursor) {
                self.remove_row(cursor);
                if cursor > 0 && cursor >= self.n_rows() {
                    self.set_cursor(cursor - 1);
                }
                *self.status() = None;
            } else {
                *self.status() = Some(format!("press d/Delete again to delete `{label}`"));
            }
        } else {
            self.delete().disarm();
            *self.status() = None;
        }
        Self::stay_result()
    }

    fn handle_activate_key(&mut self) -> Self::Result {
        let cursor = self.cursor();
        if cursor < self.n_rows() {
            self.delete().disarm();
            self.activate_row(cursor)
        } else if cursor == self.add_row_idx() {
            self.delete().disarm();
            self.begin_add();
            Self::stay_result()
        } else if Some(cursor) == self.continue_idx() {
            self.delete().disarm();
            Self::continue_result()
        } else if Some(cursor) == self.save_idx() {
            self.delete().disarm();
            Self::save_result()
        } else {
            Self::stay_result()
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Self::Result {
        if self.is_browsing() {
            self.handle_browse_key(key)
        } else {
            self.handle_edit_key(key)
        }
    }
}

/// Multi-row header list. Browsing the rows is inline; adding or
/// editing a header opens a name/value popup (see
/// [`render_header_edit_popup`]).
///
/// Layout (visible "rows" the cursor can land on):
///   - 0..n               actual header rows
///   - n                  `[+ add header]`
///   - n+1                `[continue →]` (used by the Add wizard)
///
/// In Browse mode the cursor selects a row and `Tab`/`Shift+Tab` move
/// like `↓`/`↑`. With the popup open, `Tab`/`Shift+Tab` switch between
/// the name and value fields, `enter` saves, and `esc` cancels.
pub(in crate::tui::settings) struct HeaderEditor {
    pub(in crate::tui::settings) rows: Vec<HeaderSpec>,
    pub(in crate::tui::settings) cursor: usize,
    pub(in crate::tui::settings) mode: HeaderMode,
    pub(in crate::tui::settings) name_buf: TextField,
    pub(in crate::tui::settings) value_buf: TextField,
    /// Row the popup is editing; `None` while adding a brand-new header.
    /// A new header is committed to `rows` only on save, so cancelling
    /// an add leaves no blank row behind.
    pub(in crate::tui::settings) edit_target: Option<usize>,
    /// If false, the synthetic `[continue →]` row is suppressed (used
    /// from the Edit page, where there's no next step).
    pub(in crate::tui::settings) show_continue: bool,
    pub(in crate::tui::settings) delete: RowDeleteConfirm,
    pub(in crate::tui::settings) status: Option<String>,
}

pub(in crate::tui::settings) enum HeaderMode {
    Browse,
    /// Popup open, focused on the name field.
    EditName,
    /// Popup open, focused on the value field.
    EditValue,
}

pub(in crate::tui::settings) enum HeaderResult {
    Stay,
    Continue,
    Back,
    /// `[save changes]` row / `s` accelerator (Edit-page sub-page only):
    /// commit the provider entry to disk and stay on the page.
    Save,
}

impl RowListEditor for HeaderEditor {
    type Result = HeaderResult;

    fn n_rows(&self) -> usize {
        self.rows.len()
    }

    fn cursor(&self) -> usize {
        self.cursor
    }

    fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor;
    }

    fn is_browsing(&self) -> bool {
        matches!(self.mode, HeaderMode::Browse)
    }

    fn delete(&mut self) -> &mut RowDeleteConfirm {
        &mut self.delete
    }

    fn status(&mut self) -> &mut Option<String> {
        &mut self.status
    }

    fn delete_label(&self, index: usize) -> String {
        self.rows[index].name.clone()
    }

    fn remove_row(&mut self, index: usize) {
        self.rows.remove(index);
    }

    /// The `[continue ->]` row index (Add wizard only).
    fn continue_idx(&self) -> Option<usize> {
        if self.show_continue {
            Some(self.n_rows() + 1)
        } else {
            None
        }
    }

    /// The `[save changes]` row index (Edit-page sub-page only - mutually
    /// exclusive with `[continue ->]`, which only the Add wizard shows).
    fn save_idx(&self) -> Option<usize> {
        if self.show_continue {
            None
        } else {
            Some(self.n_rows() + 1)
        }
    }

    fn start_add(&mut self) {
        self.edit_target = None;
        self.name_buf = TextField::default();
        self.value_buf = TextField::default();
        self.mode = HeaderMode::EditName;
    }

    fn start_edit(&mut self, index: usize) {
        let row = &self.rows[index];
        self.edit_target = Some(index);
        self.name_buf = TextField::new(row.name.clone());
        self.value_buf = TextField::new(row.value.clone());
        // Start on the value - the field most often changed when editing an
        // existing header.
        self.mode = HeaderMode::EditValue;
    }

    /// Save the popup buffers. A new header with an empty name is discarded so
    /// a stray `a` leaves no blank row; edits to an existing row are always
    /// written so a field can be cleared.
    fn commit_edit_fields(&mut self) -> Result<(), String> {
        let name = self.name_buf.text().trim().to_string();
        let value = self.value_buf.text().to_string();
        match self.edit_target {
            Some(index) => {
                if let Some(row) = self.rows.get_mut(index) {
                    row.name = name;
                    row.value = value;
                    self.cursor = index;
                }
            }
            None => {
                if !name.is_empty() {
                    self.rows.push(HeaderSpec { name, value });
                    self.cursor = self.rows.len() - 1;
                }
            }
        }
        Ok(())
    }

    fn finish_edit(&mut self) {
        self.edit_target = None;
        self.mode = HeaderMode::Browse;
    }

    fn cycle_edit_focus(&mut self, _reverse: bool) {
        self.mode = match self.mode {
            HeaderMode::EditName => HeaderMode::EditValue,
            _ => HeaderMode::EditName,
        };
    }

    fn handle_edit_input(&mut self, key: KeyEvent) {
        match self.mode {
            HeaderMode::EditName => {
                self.name_buf.handle_key(key);
            }
            HeaderMode::EditValue => {
                self.value_buf.handle_key(key);
            }
            HeaderMode::Browse => {}
        }
    }

    fn stay_result() -> Self::Result {
        HeaderResult::Stay
    }

    fn back_result() -> Self::Result {
        HeaderResult::Back
    }

    fn save_result() -> Self::Result {
        HeaderResult::Save
    }

    fn continue_result() -> Self::Result {
        HeaderResult::Continue
    }

    fn activate_row(&mut self, index: usize) -> Self::Result {
        <Self as RowListEditor>::begin_edit(self, index);
        HeaderResult::Stay
    }
}

impl HeaderEditor {
    pub(in crate::tui::settings) fn new(rows: Vec<HeaderSpec>, show_continue: bool) -> Self {
        Self {
            rows,
            cursor: 0,
            mode: HeaderMode::Browse,
            name_buf: TextField::default(),
            value_buf: TextField::default(),
            edit_target: None,
            show_continue,
            delete: RowDeleteConfirm::default(),
            status: None,
        }
    }

    pub(in crate::tui::settings) fn add_row_idx(&self) -> usize {
        <Self as RowListEditor>::add_row_idx(self)
    }

    pub(in crate::tui::settings) fn continue_idx(&self) -> Option<usize> {
        <Self as RowListEditor>::continue_idx(self)
    }

    pub(in crate::tui::settings) fn save_idx(&self) -> Option<usize> {
        <Self as RowListEditor>::save_idx(self)
    }

    pub(in crate::tui::settings) fn cancel_edit(&mut self) {
        <Self as RowListEditor>::cancel_edit(self);
    }

    pub(in crate::tui::settings) fn handle_key(&mut self, key: KeyEvent) -> HeaderResult {
        <Self as RowListEditor>::handle_key(self, key)
    }

    /// The field a paste should land in: the name/value buffer matching the
    /// popup focus (`mode`), or `None` while browsing (no field is open).
    pub(in crate::tui::settings) fn active_text_field(&mut self) -> Option<&mut TextField> {
        match self.mode {
            HeaderMode::EditName => Some(&mut self.name_buf),
            HeaderMode::EditValue => Some(&mut self.value_buf),
            HeaderMode::Browse => None,
        }
    }

    pub(in crate::tui::settings) fn rows(&self) -> &[HeaderSpec] {
        &self.rows
    }

    pub(in crate::tui::settings) fn is_editing(&self) -> bool {
        !matches!(self.mode, HeaderMode::Browse)
    }
}

/// Multi-row model list manager for the provider Edit page. Browsing the
/// rows is inline; adding or editing a *manual* entry opens an
/// id/name/context popup (see [`render_model_edit_popup`]).
///
/// Layout (visible "rows" the cursor can land on):
///   - 0..n   actual model rows (fetched + manual, in list order)
///   - n      `[+ add model]`
///
/// Only manual entries can be edited (id / name / context). Any entry —
/// fetched or manual — can be deleted; a deleted fetched entry reappears
/// on the next `/models` refetch.
pub(in crate::tui::settings) struct ModelEditor {
    /// Effective template identity of the provider whose models are being
    /// edited ([`ProviderEntry::effective_template`]), resolved from the
    /// loaded config at construction. Only scopes template-specific defaults
    /// applied to newly added manual entries ([`apply_template_model_defaults`]);
    /// `None` for providers with no known template.
    pub(in crate::tui::settings) template: Option<String>,
    pub(in crate::tui::settings) rows: Vec<ModelEntry>,
    pub(in crate::tui::settings) cursor: usize,
    pub(in crate::tui::settings) mode: ModelMode,
    pub(in crate::tui::settings) id_buf: TextField,
    pub(in crate::tui::settings) name_buf: TextField,
    pub(in crate::tui::settings) context_buf: TextField,
    /// Row the popup is editing; `None` while adding a brand-new entry.
    pub(in crate::tui::settings) edit_target: Option<usize>,
    /// Field the popup is focused on while editing.
    pub(in crate::tui::settings) focus: ModelField,
    /// Transient validation/status message shown under the editor.
    pub(in crate::tui::settings) status: Option<String>,
    pub(in crate::tui::settings) delete: RowDeleteConfirm,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub(in crate::tui::settings) enum ModelField {
    Id,
    Name,
    Context,
}

pub(in crate::tui::settings) enum ModelMode {
    Browse,
    /// id/name/context popup open (add or edit).
    Edit,
}

pub(in crate::tui::settings) enum ModelResult {
    Stay,
    Back,
    /// `[save changes]` row / `s` accelerator: commit the provider entry
    /// (with the live model rows) to disk and stay on the page.
    Save,
    /// Open the model-settings sub-dialog for the row at this index
    /// (implementation note). Works on every model — these
    /// are overrides, not edits to fetched data.
    OpenSettings(usize),
}

impl RowListEditor for ModelEditor {
    type Result = ModelResult;

    fn n_rows(&self) -> usize {
        self.rows.len()
    }

    fn cursor(&self) -> usize {
        self.cursor
    }

    fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor;
    }

    fn is_browsing(&self) -> bool {
        matches!(self.mode, ModelMode::Browse)
    }

    fn delete(&mut self) -> &mut RowDeleteConfirm {
        &mut self.delete
    }

    fn status(&mut self) -> &mut Option<String> {
        &mut self.status
    }

    fn delete_label(&self, index: usize) -> String {
        self.rows[index].id.clone()
    }

    fn remove_row(&mut self, index: usize) {
        self.rows.remove(index);
    }

    /// The `[save changes]` row index (always present - the Models page is only
    /// reached from the provider Edit page).
    fn save_idx(&self) -> Option<usize> {
        Some(self.n_rows() + 1)
    }

    fn start_add(&mut self) {
        self.edit_target = None;
        self.id_buf = TextField::default();
        self.name_buf = TextField::default();
        self.context_buf = TextField::default();
        self.focus = ModelField::Id;
        self.mode = ModelMode::Edit;
    }

    fn start_edit(&mut self, index: usize) {
        let row = &self.rows[index];
        self.edit_target = Some(index);
        self.id_buf = TextField::new(row.id.clone());
        self.name_buf = TextField::new(row.name.clone().unwrap_or_default());
        self.context_buf = TextField::new(
            row.context_length
                .map(|context| context.to_string())
                .unwrap_or_default(),
        );
        self.focus = ModelField::Id;
        self.mode = ModelMode::Edit;
    }

    /// Validate the popup buffers and, if valid, commit them to `rows`.
    /// Returns `Err(message)` on validation failure (kept open) and `Ok(())` on
    /// a successful commit (popup closed by the shared editor skeleton).
    fn commit_edit_fields(&mut self) -> Result<(), String> {
        let id = self.id_buf.text().trim().to_string();
        if id.is_empty() {
            return Err("model id cannot be empty".to_string());
        }
        // Reject a duplicate id within this provider, ignoring the row being
        // edited so a no-op id keeps validating.
        let dup = self
            .rows
            .iter()
            .enumerate()
            .any(|(index, model)| model.id == id && Some(index) != self.edit_target);
        if dup {
            return Err(format!("a model with id `{id}` already exists"));
        }
        let name_raw = self.name_buf.text().trim();
        let name = if name_raw.is_empty() {
            None
        } else {
            Some(name_raw.to_string())
        };
        let context_raw = self.context_buf.text().trim();
        let context_length = if context_raw.is_empty() {
            None
        } else {
            match context_raw.parse::<u32>() {
                Ok(context) => Some(context),
                Err(_) => return Err("context length must be a number".to_string()),
            }
        };

        match self.edit_target {
            Some(index) => {
                if let Some(row) = self.rows.get_mut(index) {
                    row.id = id;
                    row.name = name;
                    row.context_length = context_length;
                    self.cursor = index;
                }
            }
            None => {
                let mut entry = ModelEntry {
                    id,
                    name,
                    thinking_modes: Vec::new(),
                    inputs: None,
                    context_length,
                    favorite: false,
                    manual: true,
                    trust: None,
                    location: None,
                    quality_rank: None,
                    cost_rank: None,
                    subagent_invokable: None,
                    can_delegate: None,
                    embeddings: None,
                    embedding_dimensions: None,
                    availability: Default::default(),
                    cache: None,
                    shrink: None,
                    context: None,
                    auto_prune: None,
                    timeout: None,
                    backup: None,
                    mode: None,
                    system_prompt: None,
                    inline_think: None,
                    hint_tool_call_corrections: None,
                    text_embedded_recovery: None,
                    thinking_params: Default::default(),
                    wire_api: Default::default(),
                    extra: Default::default(),
                    capabilities: Default::default(),
                    capability_overrides: Default::default(),
                    provider_metadata: Default::default(),
                };
                // A hand-added model gets the same template-scoped defaults a
                // `/models` discovery would apply (z.ai has no `/models`
                // endpoint, so manual add IS its discovery).
                apply_template_model_defaults(self.template.as_deref(), &mut entry);
                self.rows.push(entry);
                self.cursor = self.rows.len() - 1;
            }
        }
        Ok(())
    }

    fn finish_edit(&mut self) {
        self.edit_target = None;
        self.mode = ModelMode::Browse;
    }

    fn on_cancel_edit(&mut self) {
        self.status = None;
    }

    fn cycle_edit_focus(&mut self, reverse: bool) {
        self.focus = match (self.focus, reverse) {
            (ModelField::Id, false) => ModelField::Name,
            (ModelField::Name, false) => ModelField::Context,
            (ModelField::Context, false) => ModelField::Id,
            (ModelField::Id, true) => ModelField::Context,
            (ModelField::Name, true) => ModelField::Id,
            (ModelField::Context, true) => ModelField::Name,
        };
    }

    fn handle_edit_input(&mut self, key: KeyEvent) {
        match self.focus {
            ModelField::Id => {
                self.id_buf.handle_key(key);
            }
            ModelField::Name => {
                self.name_buf.handle_key(key);
            }
            ModelField::Context => {
                self.context_buf.handle_key(key);
            }
        }
    }

    fn stay_result() -> Self::Result {
        ModelResult::Stay
    }

    fn back_result() -> Self::Result {
        ModelResult::Back
    }

    fn save_result() -> Self::Result {
        ModelResult::Save
    }

    fn activate_row(&mut self, index: usize) -> Self::Result {
        ModelResult::OpenSettings(index)
    }

    fn handle_save_shortcut(&mut self) -> Self::Result {
        self.delete.disarm();
        ModelResult::Save
    }

    fn handle_custom_browse_key(&mut self, key: KeyEvent) -> Option<Self::Result> {
        if !matches!(key.code, KeyCode::Char('r')) {
            return None;
        }

        if self.cursor < self.rows.len() {
            self.delete.disarm();
            if self.rows[self.cursor].manual {
                <Self as RowListEditor>::begin_edit(self, self.cursor);
            } else {
                self.status = Some("fetched models can't be renamed (settings: enter)".to_string());
            }
        }
        Some(ModelResult::Stay)
    }
}

impl ModelEditor {
    pub(in crate::tui::settings) fn new(template: Option<String>, rows: Vec<ModelEntry>) -> Self {
        Self {
            template,
            rows,
            cursor: 0,
            mode: ModelMode::Browse,
            id_buf: TextField::default(),
            name_buf: TextField::default(),
            context_buf: TextField::default(),
            edit_target: None,
            focus: ModelField::Id,
            status: None,
            delete: RowDeleteConfirm::default(),
        }
    }

    pub(in crate::tui::settings) fn add_row_idx(&self) -> usize {
        <Self as RowListEditor>::add_row_idx(self)
    }

    pub(in crate::tui::settings) fn save_idx(&self) -> usize {
        <Self as RowListEditor>::save_idx(self).expect("model editor has a save row")
    }

    pub(in crate::tui::settings) fn selected_enter_hint(&self) -> &'static str {
        if self.cursor < self.rows.len() {
            if self.rows[self.cursor].manual {
                "enter: settings"
            } else {
                "enter: read-only settings"
            }
        } else if self.cursor == self.add_row_idx() {
            "enter: add model"
        } else if self.cursor == self.save_idx() {
            "enter: save changes"
        } else {
            "enter: settings"
        }
    }

    pub(in crate::tui::settings) fn cancel_edit(&mut self) {
        <Self as RowListEditor>::cancel_edit(self);
    }

    pub(in crate::tui::settings) fn handle_key(&mut self, key: KeyEvent) -> ModelResult {
        <Self as RowListEditor>::handle_key(self, key)
    }

    /// The field a paste should land in: the id/name/context buffer matching
    /// the popup focus, or `None` while browsing (no popup open).
    pub(in crate::tui::settings) fn active_text_field(&mut self) -> Option<&mut TextField> {
        match self.mode {
            ModelMode::Browse => None,
            ModelMode::Edit => Some(match self.focus {
                ModelField::Id => &mut self.id_buf,
                ModelField::Name => &mut self.name_buf,
                ModelField::Context => &mut self.context_buf,
            }),
        }
    }

    pub(in crate::tui::settings) fn rows(&self) -> &[ModelEntry] {
        &self.rows
    }

    pub(in crate::tui::settings) fn is_editing(&self) -> bool {
        matches!(self.mode, ModelMode::Edit)
    }
}
