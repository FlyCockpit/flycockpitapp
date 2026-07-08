//! Shared secret-display helpers for settings surfaces.

pub(super) const MASKED_VALUE: &str = "********";

pub(super) fn mask_value() -> &'static str {
    MASKED_VALUE
}

pub(super) fn is_mask_value(value: &str) -> bool {
    value.trim() == MASKED_VALUE
}

pub(super) fn masked_list_summary(values: &[String]) -> String {
    if values.is_empty() {
        "(none)".to_string()
    } else {
        format!("{} value(s) masked", values.len())
    }
}

pub(super) fn masked_list_item(index: usize) -> String {
    format!("{} #{}", MASKED_VALUE, index + 1)
}
