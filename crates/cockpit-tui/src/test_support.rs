//! Feature-gated TUI test facade.
//!
//! Golden screen dumps: [`golden`]. Response-performance e2e:
//! [`ResponsePerformanceE2eInput`], [`ResponsePerformanceE2eHarness`],
//! [`ResponsePerformanceE2eObservation`].

pub mod golden {
    pub use crate::tui::app::golden::*;
    pub use crate::tui::golden::*;
}
pub use crate::tui::app::response_performance_e2e::{
    ResponsePerformanceE2eHarness, ResponsePerformanceE2eInput, ResponsePerformanceE2eObservation,
};
