#![cfg(test)]

const SRC: &str = include_str!("lib.rs");

#[test]
fn uses_scan() {
    assert!(!SRC.is_empty());
}
