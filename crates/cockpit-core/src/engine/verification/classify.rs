//! Minimal, hardcoded ToolClass classifier for risky-action verification.
//!
//! A future change should make [`crate::agents::ToolClass`] a declared field
//! on standard tool definitions; until then this mapping is the only
//! production classifier.

use crate::agents::ToolClass;

/// Classify an ordinary tool name for verification matching.
///
/// Classifies the three authoring self-verification surfaces. Every other name
/// remains unclassified.
pub(crate) fn classify_tool(tool_id: &str) -> Option<ToolClass> {
    match tool_id {
        "write" | "edit" | "delete" => Some(ToolClass::ArtifactWrite),
        "bash" => Some(ToolClass::Command),
        "mcp" => Some(ToolClass::Monty),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_maps_command_and_monty_surfaces() {
        // Authoring self-verification surfaces, including `delete`.
        for (name, class) in [
            ("write", ToolClass::ArtifactWrite),
            ("edit", ToolClass::ArtifactWrite),
            ("delete", ToolClass::ArtifactWrite),
            ("bash", ToolClass::Command),
            ("mcp", ToolClass::Monty),
        ] {
            assert_eq!(classify_tool(name), Some(class), "{name}");
        }

        for name in [
            "read", "search", "grep", "glob", "shell", "task", "question",
        ] {
            assert_eq!(classify_tool(name), None, "{name}");
        }
    }
}
