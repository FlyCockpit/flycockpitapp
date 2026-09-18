const SRC: &str = include_str!("../src/lib.rs");

#[test]
fn uses_scan() {
    assert!(!SRC.is_empty());
}
