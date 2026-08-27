//! Computer-use guidance proposal enablement-trace display for TUI settings
//! (issue #59, AC2).
//!
//! Surfaces the four `allow_computer_guidance_proposals` config layers (global,
//! canonical machine-local project, provider, model), each as
//! `absent | enabled | disabled`, plus the effective boolean, whether a sticky
//! disable veto is present, and the config generation the resolution was
//! stamped under.
//!
//! This module is pure presentation logic: it formats
//! [`EnablementResolution`] + a config generation into display lines the TUI
//! settings pane renders. The resolution itself is computed in-process via
//! [`cockpit_core::computer::guidance::enablement::resolve_guidance_enablement`]
//! (the TUI already holds the layered config + providers), so no new daemon
//! RPC is required for the trace.

use cockpit_core::computer::guidance::{EnablementLayers, EnablementResolution, EnablementValue};

/// One contributing layer in the trace, with a stable display label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuidanceTraceLayer {
    pub label: &'static str,
    pub value: EnablementValue,
}

impl GuidanceTraceLayer {
    /// The display string for this layer's value.
    pub fn value_label(self) -> &'static str {
        match self.value {
            EnablementValue::Absent => "absent",
            EnablementValue::Enabled => "enabled",
            EnablementValue::Disabled => "disabled (veto)",
        }
    }
}

/// The full enablement trace: the ordered layer list, the effective boolean,
/// the sticky-disable-veto flag, and the config generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuidanceEnablementTraceLines {
    pub layers: Vec<GuidanceTraceLayer>,
    pub enabled: bool,
    pub has_disable_veto: bool,
    pub config_generation: u64,
}

/// Format an [`EnablementResolution`] + `config_generation` into the trace
/// display data (AC2). Layers appear in broadest-to-narrowest order: global,
/// project, provider, model.
pub fn format_enablement_trace(
    resolution: &EnablementResolution,
    config_generation: u64,
) -> GuidanceEnablementTraceLines {
    let layers = layer_list(resolution.layers);
    GuidanceEnablementTraceLines {
        layers,
        enabled: resolution.enabled,
        has_disable_veto: resolution.has_disable_veto,
        config_generation,
    }
}

/// The ordered layer list from [`EnablementLayers`].
pub fn layer_list(layers: EnablementLayers) -> Vec<GuidanceTraceLayer> {
    vec![
        GuidanceTraceLayer {
            label: "global",
            value: layers.global,
        },
        GuidanceTraceLayer {
            label: "project",
            value: layers.project,
        },
        GuidanceTraceLayer {
            label: "provider",
            value: layers.provider,
        },
        GuidanceTraceLayer {
            label: "model",
            value: layers.model,
        },
    ]
}

/// Render the trace as plain display lines (one per layer, then a summary).
/// Suitable for a ratatui `Paragraph` or a settings list. Plain text only —
/// no markup.
pub fn render_trace_lines(trace: &GuidanceEnablementTraceLines) -> Vec<String> {
    let mut out = Vec::with_capacity(trace.layers.len() + 2);
    out.push(format!(
        "Computer-use guidance proposals: {}",
        if trace.enabled { "enabled" } else { "disabled" }
    ));
    for layer in &trace.layers {
        out.push(format!("  {} = {}", layer.label, layer.value_label()));
    }
    if trace.has_disable_veto {
        out.push("  (a disable at one layer is a sticky veto)".to_string());
    }
    out.push(format!("  config generation: {}", trace.config_generation));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layers(
        global: EnablementValue,
        project: EnablementValue,
        provider: EnablementValue,
        model: EnablementValue,
    ) -> EnablementLayers {
        EnablementLayers {
            global,
            project,
            provider,
            model,
        }
    }

    #[test]
    fn all_absent_resolves_disabled_with_absent_layers() {
        let res = cockpit_core::computer::guidance::resolve_enablement(&layers(
            EnablementValue::Absent,
            EnablementValue::Absent,
            EnablementValue::Absent,
            EnablementValue::Absent,
        ));
        let trace = format_enablement_trace(&res, 7);
        assert!(!trace.enabled);
        assert!(!trace.has_disable_veto);
        assert_eq!(trace.config_generation, 7);
        assert_eq!(trace.layers.len(), 4);
        assert!(
            trace
                .layers
                .iter()
                .all(|l| l.value == EnablementValue::Absent)
        );
        let lines = render_trace_lines(&trace);
        assert!(lines[0].contains("disabled"));
        assert!(lines.iter().any(|l| l.contains("config generation: 7")));
    }

    #[test]
    fn provider_enable_with_no_veto_resolves_enabled() {
        let res = cockpit_core::computer::guidance::resolve_enablement(&layers(
            EnablementValue::Absent,
            EnablementValue::Absent,
            EnablementValue::Enabled,
            EnablementValue::Absent,
        ));
        let trace = format_enablement_trace(&res, 1);
        assert!(trace.enabled);
        assert!(!trace.has_disable_veto);
        let lines = render_trace_lines(&trace);
        assert!(lines[0].contains("enabled"));
        assert!(lines.iter().any(|l| l.contains("provider = enabled")));
    }

    #[test]
    fn sticky_disable_veto_shown_even_when_a_narrower_layer_enables() {
        let res = cockpit_core::computer::guidance::resolve_enablement(&layers(
            EnablementValue::Disabled,
            EnablementValue::Absent,
            EnablementValue::Enabled,
            EnablementValue::Absent,
        ));
        let trace = format_enablement_trace(&res, 2);
        assert!(!trace.enabled, "global disable is a sticky veto");
        assert!(trace.has_disable_veto);
        let lines = render_trace_lines(&trace);
        assert!(lines[0].contains("disabled"));
        assert!(lines.iter().any(|l| l.contains("sticky veto")));
        assert!(lines.iter().any(|l| l.contains("global = disabled (veto)")));
        assert!(lines.iter().any(|l| l.contains("provider = enabled")));
    }
}
