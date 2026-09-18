pub fn marker() {}

#[test]
fn scans_source() {
    let _ = include_str!("lib.rs");
}
