//! Minimal, hardcoded ToolClass classifier for ArtifactWrite verification.
//!
//! A future change should make [`crate::agents::ToolClass`] a declared field
//! on standard tool definitions; until then this mapping is the only
//! production classifier.

use crate::agents::ToolClass;

/// Classify an ordinary tool name for verification matching.
///
/// Returns [`ToolClass::ArtifactWrite`] for `write`/`edit` and the plan
/// variants (`plan_write`/`plan_edit`) when those tools are granted (a
/// dispatch that reaches this function has already been granted). Every
/// other name is unclassified: no verification rule can match it yet.
pub(crate) fn classify_tool(tool_id: &str) -> Option<ToolClass> {
    match tool_id {
        "write" | "edit" | "plan_write" | "plan_edit" => Some(ToolClass::ArtifactWrite),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_maps_write_edit_and_plan_variants_to_artifact_write() {
        for name in ["write", "edit", "plan_write", "plan_edit"] {
            assert_eq!(
                classify_tool(name),
                Some(ToolClass::ArtifactWrite),
                "{name}"
            );
        }
    }

    #[test]
    fn classifier_leaves_non_write_tools_unclassified() {
        for name in ["read", "bash", "search", "grep", "glob", "task", "question"] {
            assert_eq!(classify_tool(name), None, "{name}");
        }
    }
}
