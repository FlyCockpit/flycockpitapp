pub fn marker() {}

#[test]
fn scans_concat_path() {
    let _ = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
}
