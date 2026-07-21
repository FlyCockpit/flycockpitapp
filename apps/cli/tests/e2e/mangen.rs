//! Man-page generation tests for release packaging.

#[test]
fn mangen_generates_and_hides_hidden() {
    let tempdir = tempfile::tempdir().expect("tempdir");

    cockpit_cli::manpages::generate_manpages(tempdir.path()).expect("generate man pages");

    let main_page = tempdir.path().join("cockpit.1");
    assert!(main_page.is_file(), "main man page should exist");

    let rendered = std::fs::read_to_string(&main_page).expect("read main man page");
    assert!(rendered.contains("AI coding harness"));
    assert!(!rendered.contains("pure"), "hidden --pure must not render");
}
