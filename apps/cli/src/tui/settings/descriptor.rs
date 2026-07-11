#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum FieldKind {
    Cycle,
    EditText,
    Numeric,
    Drill,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) struct SettingDescriptor {
    pub(super) label: &'static str,
    pub(super) help: &'static str,
    pub(super) kind: FieldKind,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) struct SettingHeading {
    pub(super) title: &'static str,
    pub(super) blurb: &'static str,
}

pub(super) trait SettingStore {
    type Id: Copy;

    fn descriptor(&self, id: Self::Id) -> SettingDescriptor;
    fn value(&self, id: Self::Id) -> String;
    fn cycle(&mut self, id: Self::Id);
    fn commit_text(&mut self, id: Self::Id, raw: &str) -> Result<(), String>;
}
