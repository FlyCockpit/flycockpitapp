//! Clean fixture: production `include_str!` of `.rs` is allowed.
const HELPER: &str = include_str!("helper.rs");

pub fn marker() -> &'static str {
    HELPER
}

#[cfg(test)]
mod tests {
    const JSON: &str = include_str!("fixture.json");

    #[test]
    fn json_fixture_is_allowed() {
        // include_str!("helper.rs")
        let _quoted = "include_str!(\"helper.rs\")";
        assert!(JSON.contains("ok"));
        assert!(!crate::HELPER.is_empty());
    }
}
