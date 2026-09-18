const JSON: &str = include_str!("../src/fixture.json");

#[test]
fn integration_json_is_allowed() {
    assert!(JSON.contains("ok"));
}
