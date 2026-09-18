mod clouds;
mod plane;
mod scene;
mod titles;

#[cfg(any(test, feature = "test-support"))]
pub(crate) use scene::{COCKPIT_FRAME, FLIGHT_FRAMES};
pub(crate) use scene::{PROMPT_FRAME, Scene};
