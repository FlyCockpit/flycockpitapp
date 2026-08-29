//! Feature-gated TUI test facade for the response-performance e2e harness.
//!
//! Public surface is exactly three names: [`ResponsePerformanceE2eInput`],
//! [`ResponsePerformanceE2eHarness`], and [`ResponsePerformanceE2eObservation`].

pub use crate::tui::app::response_performance_e2e::{
    ResponsePerformanceE2eHarness, ResponsePerformanceE2eInput, ResponsePerformanceE2eObservation,
};
