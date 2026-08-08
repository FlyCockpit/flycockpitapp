//! Strict parser for the shared remote binary-magic namespace.
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MagicOwner {
    pub magic: String,
    pub symbolic_type: String,
    pub owning_package: String,
    pub owning_version: u8,
}
pub fn parse_registry(json: &str) -> Result<Vec<MagicOwner>, String> {
    let xs: Vec<MagicOwner> = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if xs.is_empty() {
        return Err("magic registry must be nonempty".into());
    }
    let mut m = HashSet::new();
    let mut t = HashSet::new();
    let mut previous = "";
    for x in &xs {
        if x.magic.len() != 4
            || !x.magic.starts_with("FC")
            || !x.magic[2..]
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            || x.magic.as_str() <= previous
            || !m.insert(x.magic.clone())
            || x.symbolic_type.is_empty()
            || !t.insert(x.symbolic_type.clone())
            || x.owning_package.is_empty()
            || x.owning_version != 1
        {
            return Err("invalid, unsorted, duplicate, or ownerless magic entry".into());
        }
        previous = &x.magic;
    }
    Ok(xs)
}
pub fn assert_registered(registry: &[MagicOwner], declared: &[(&str, &str)]) -> Result<(), String> {
    for (magic, symbol) in declared {
        if !registry
            .iter()
            .any(|x| x.magic == *magic && x.symbolic_type == *symbol)
        {
            return Err(format!("unregistered production codec {magic}"));
        }
    }
    Ok(())
}
