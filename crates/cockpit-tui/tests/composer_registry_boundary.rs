use std::fs;
use std::path::Path;

#[test]
fn app_whole_buffer_edits_use_registry_aware_helpers() {
    let app_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tui/app");
    let mut violations = Vec::new();
    for entry in fs::read_dir(&app_dir).expect("read app source directory") {
        let path = entry.expect("read app source entry").path();
        if path.extension().and_then(|value| value.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().and_then(|value| value.to_str()).unwrap();
        if name == "mod.rs" || name == "btw_pane.rs" || name.ends_with("_tests.rs") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("read app source");
        for (line_index, line) in source.lines().enumerate() {
            if line.contains("self.composer.set(") || line.contains("self.composer.clear(") {
                violations.push(format!("{}:{}: {}", path.display(), line_index + 1, line));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "whole-buffer composer edits bypass PasteRegistry authority:\n{}",
        violations.join("\n")
    );
}

#[test]
fn app_registry_helpers_are_the_only_root_composer_set_clear_seam() {
    let source = include_str!("../src/tui/app/mod.rs");
    assert_eq!(source.matches("self.composer.set(").count(), 2);
    assert_eq!(source.matches("self.composer.clear(").count(), 1);
    assert!(source.contains("fn replace_composer_buffer"));
    assert!(source.contains("fn clear_composer_buffer"));
    assert!(source.contains("fn rebuild_composer_buffer"));
}

#[test]
fn whole_buffer_replacement_repros_are_pinned_to_registry_seam() {
    let input = include_str!("../src/tui/app/input.rs");
    assert!(input.contains("replace_composer_buffer(completions[chosen].clone())"));

    let async_actions = include_str!("../src/tui/app/async_actions.rs");
    assert!(async_actions.contains("replace_composer_buffer(seed)"));

    let panes = include_str!("../src/tui/app/panes.rs");
    assert!(panes.contains("rebuild_composer_buffer(rebuilt)"));
}
