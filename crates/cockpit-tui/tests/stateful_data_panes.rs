use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("cockpit-tui must remain under crates/")
        .to_path_buf()
}

#[test]
fn simple_data_panes_keep_stateful_widget_and_buffer_contracts() {
    let root = workspace_root();
    for pane in ["stats_pane.rs", "permissions_pane.rs", "resources_pane.rs"] {
        let path = root.join("crates/cockpit-tui/src/tui").join(pane);
        let source = fs::read_to_string(&path).expect("read data pane source");
        assert!(
            !source.contains("ScrollList"),
            "{pane} must use durable ratatui widget state"
        );
        assert!(
            !source.contains("Paragraph::new(lines).scroll"),
            "{pane} must not recreate list viewport mechanics with Paragraph"
        );
        for required in ["ListState", "List::new", "ScrollbarState", "TestBackend"] {
            assert!(
                source.contains(required),
                "{pane} must retain its {required} contract"
            );
        }
    }
}
