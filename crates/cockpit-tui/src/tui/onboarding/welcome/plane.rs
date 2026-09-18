use cockpit_core::banner::{RENDERED_HEIGHT, RENDERED_WIDTH, ResolvedCell, p51_cells};

pub(super) const WIDTH: u16 = RENDERED_WIDTH as u16;
pub(super) const HEIGHT: u16 = RENDERED_HEIGHT as u16;
const PHASE_FRAMES: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PropPhase(pub(super) u8);

impl PropPhase {
    pub(super) fn for_frame(frame: usize) -> Self {
        Self(((frame / PHASE_FRAMES) % 4) as u8)
    }
}

pub(super) fn cells(frame: usize) -> Vec<Vec<ResolvedCell>> {
    p51_cells(PropPhase::for_frame(frame).0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propeller_phase_stays_in_four_phase_range() {
        for frame in 0..200 {
            assert!(PropPhase::for_frame(frame).0 <= 3);
        }
        assert_eq!(PropPhase::for_frame(0).0, 0);
        assert_eq!(PropPhase::for_frame(2).0, 1);
        assert_eq!(PropPhase::for_frame(6).0, 3);
        assert_eq!(PropPhase::for_frame(8).0, 0);
    }
}
