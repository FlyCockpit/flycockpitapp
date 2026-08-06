//! X11/RandR target-evidence pure logic.
//!
//! Session identity is a domain hash over transport/display/screen plus
//! length-delimited server setup vendor/release and root-window identity.
//! Xauthority cookie bytes never enter the identity.

use crate::computer::host_identity::domain_hash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X11SessionParts {
    pub transport: String,
    pub display_number: u32,
    pub screen: u32,
    pub vendor: String,
    pub release: u32,
    pub root_window_id: u32,
    /// Cookie bytes are credentials only — never hashed into identity.
    pub xauthority_cookie: Vec<u8>,
}

pub fn x11_session_or_seat_id(parts: &X11SessionParts) -> [u8; 32] {
    // Intentionally omit xauthority_cookie.
    domain_hash(
        b"cockpit.x11.session.v1",
        &[
            parts.transport.as_bytes(),
            &parts.display_number.to_le_bytes(),
            &parts.screen.to_le_bytes(),
            parts.vendor.as_bytes(),
            &parts.release.to_le_bytes(),
            &parts.root_window_id.to_le_bytes(),
        ],
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdidValidation {
    Valid { blocks: usize },
    Missing,
    NonIntegralBlockCount,
    BadChecksum,
}

/// EDID must have integral 128-byte block count and valid checksum per block.
pub fn validate_edid(edid: Option<&[u8]>) -> EdidValidation {
    let Some(bytes) = edid else {
        return EdidValidation::Missing;
    };
    if bytes.is_empty() || bytes.len() % 128 != 0 {
        return EdidValidation::NonIntegralBlockCount;
    }
    for chunk in bytes.chunks(128) {
        let sum: u16 = chunk.iter().map(|b| *b as u16).sum();
        if !sum.is_multiple_of(256) {
            return EdidValidation::BadChecksum;
        }
    }
    EdidValidation::Valid {
        blocks: bytes.len() / 128,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RandrOutputSnapshot {
    pub screen_index: u32,
    pub connector_name: String,
    pub edid: Option<Vec<u8>>,
    pub crtc_id: Option<u32>,
    pub mode_id: Option<u32>,
    pub geometry: Option<(i16, i16, u16, u16)>,
    pub rotation: u16,
    pub connected: bool,
    /// Clone-compatible relationship token (same non-zero group = clone-compatible).
    pub clone_group: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X11EvidenceError {
    MissingRandr,
    RandrVersionTooOld,
    MissingActiveWindow,
    MissingGeometry,
    Unauthenticated,
    InvalidEdid,
    NoConnectedCrtc,
    NoMode,
    AmbiguousOutput,
    InconsistentTimestamp,
    NoIntersectingGroup,
}

pub fn stable_output_identity(output: &RandrOutputSnapshot) -> Result<[u8; 32], X11EvidenceError> {
    match validate_edid(output.edid.as_deref()) {
        EdidValidation::Valid { .. } => {}
        _ => return Err(X11EvidenceError::InvalidEdid),
    }
    let edid = output.edid.as_deref().unwrap();
    Ok(domain_hash(
        b"cockpit.x11.output.v1",
        &[
            &output.screen_index.to_le_bytes(),
            output.connector_name.as_bytes(),
            edid,
        ],
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorGroup {
    pub output_identities: Vec<[u8; 32]>,
    pub geometry: (i16, i16, u16, u16),
    pub mode_id: u32,
    pub rotation: u16,
}

impl MirrorGroup {
    pub fn physical_display_id(&self) -> [u8; 32] {
        x11_physical_display_id(&self.output_identities)
    }
}

pub fn x11_physical_display_id(sorted_output_ids: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted = sorted_output_ids.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(sorted.len());
    for id in &sorted {
        parts.push(id.as_slice());
    }
    domain_hash(b"cockpit.x11.mirror.v1", &parts)
}

/// Build mirror groups: same CRTC, or distinct CRTCs with identical
/// geometry/mode/rotation and a clone-compatible relationship.
pub fn build_mirror_groups(
    outputs: &[RandrOutputSnapshot],
) -> Result<Vec<MirrorGroup>, X11EvidenceError> {
    let mut usable = Vec::new();
    for o in outputs {
        if !o.connected {
            continue;
        }
        let crtc = o.crtc_id.ok_or(X11EvidenceError::NoConnectedCrtc)?;
        let mode = o.mode_id.ok_or(X11EvidenceError::NoMode)?;
        let geom = o.geometry.ok_or(X11EvidenceError::MissingGeometry)?;
        let id = stable_output_identity(o)?;
        usable.push((crtc, mode, geom, o.rotation, o.clone_group, id));
    }
    if usable.is_empty() {
        return Err(X11EvidenceError::NoConnectedCrtc);
    }

    // Group by (crtc) first, then merge clone-compatible distinct CRTCs.
    let mut groups: Vec<MirrorGroup> = Vec::new();
    let mut used = vec![false; usable.len()];

    for i in 0..usable.len() {
        if used[i] {
            continue;
        }
        used[i] = true;
        let (crtc_i, mode_i, geom_i, rot_i, clone_i, id_i) = usable[i];
        let mut ids = vec![id_i];
        for j in (i + 1)..usable.len() {
            if used[j] {
                continue;
            }
            let (crtc_j, mode_j, geom_j, rot_j, clone_j, id_j) = usable[j];
            let same_crtc = crtc_i == crtc_j;
            let clone_compatible = mode_i == mode_j
                && geom_i == geom_j
                && rot_i == rot_j
                && clone_i.is_some()
                && clone_i == clone_j;
            if same_crtc || clone_compatible {
                used[j] = true;
                ids.push(id_j);
            }
        }
        ids.sort();
        ids.dedup();
        groups.push(MirrorGroup {
            output_identities: ids,
            geometry: geom_i,
            mode_id: mode_i,
            rotation: rot_i,
        });
    }
    Ok(groups)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FocusedWindowGeom {
    pub x: i16,
    pub y: i16,
    pub w: u16,
    pub h: u16,
}

impl FocusedWindowGeom {
    pub fn center(&self) -> (i16, i16) {
        (
            self.x.saturating_add((self.w / 2) as i16),
            self.y.saturating_add((self.h / 2) as i16),
        )
    }

    pub fn intersection_area(&self, g: (i16, i16, u16, u16)) -> i64 {
        let (gx, gy, gw, gh) = g;
        let ax1 = self.x as i64;
        let ay1 = self.y as i64;
        let ax2 = ax1 + self.w as i64;
        let ay2 = ay1 + self.h as i64;
        let bx1 = gx as i64;
        let by1 = gy as i64;
        let bx2 = bx1 + gw as i64;
        let by2 = by1 + gh as i64;
        let ix1 = ax1.max(bx1);
        let iy1 = ay1.max(by1);
        let ix2 = ax2.min(bx2);
        let iy2 = ay2.min(by2);
        let w = (ix2 - ix1).max(0);
        let h = (iy2 - iy1).max(0);
        w * h
    }

    pub fn contains_point(g: (i16, i16, u16, u16), p: (i16, i16)) -> bool {
        let (gx, gy, gw, gh) = g;
        p.0 >= gx
            && p.1 >= gy
            && p.0 < gx.saturating_add(gw as i16)
            && p.1 < gy.saturating_add(gh as i16)
    }
}

/// Select mirror group: unique group containing window center wins before area;
/// equal maximum between distinct non-mirror groups is `ambiguous_output`.
pub fn select_mirror_group(
    groups: &[MirrorGroup],
    window: FocusedWindowGeom,
) -> Result<&MirrorGroup, X11EvidenceError> {
    if groups.is_empty() {
        return Err(X11EvidenceError::NoIntersectingGroup);
    }
    let center = window.center();
    let center_hits: Vec<usize> = groups
        .iter()
        .enumerate()
        .filter(|(_, g)| FocusedWindowGeom::contains_point(g.geometry, center))
        .map(|(i, _)| i)
        .collect();
    if center_hits.len() == 1 {
        return Ok(&groups[center_hits[0]]);
    }

    let mut best_area = -1_i64;
    let mut best_idx = None;
    let mut tie = false;
    for (i, g) in groups.iter().enumerate() {
        let area = window.intersection_area(g.geometry);
        if area <= 0 {
            continue;
        }
        if area > best_area {
            best_area = area;
            best_idx = Some(i);
            tie = false;
        } else if area == best_area && best_idx.is_some() {
            // Distinct non-mirror groups with equal max → ambiguous.
            if groups[best_idx.unwrap()].output_identities != g.output_identities {
                tie = true;
            }
        }
    }
    if tie {
        return Err(X11EvidenceError::AmbiguousOutput);
    }
    best_idx
        .map(|i| &groups[i])
        .ok_or(X11EvidenceError::NoIntersectingGroup)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X11NativeEvent {
    ActiveWindow,
    Property,
    Configure,
    Destroy,
    Randr,
    AtSpiFocus,
}

#[derive(Debug, Default)]
pub struct X11ObservedEpoch {
    pub epoch: u64,
    pub unavailable: bool,
}

impl X11ObservedEpoch {
    pub fn consume(&mut self, _ev: X11NativeEvent) -> Result<u64, X11EvidenceError> {
        if self.unavailable {
            return Err(X11EvidenceError::InconsistentTimestamp);
        }
        match self.epoch.checked_add(1) {
            Some(v) => {
                self.epoch = v;
                Ok(v)
            }
            None => {
                self.unavailable = true;
                Err(X11EvidenceError::InconsistentTimestamp)
            }
        }
    }
}

/// Validate RandR version >= 1.3 and resource timestamp consistency.
pub fn check_randr_version(major: u32, minor: u32) -> Result<(), X11EvidenceError> {
    if major > 1 || (major == 1 && minor >= 3) {
        Ok(())
    } else {
        Err(X11EvidenceError::RandrVersionTooOld)
    }
}

pub fn check_resource_timestamp(snapshot_ts: u32, current_ts: u32) -> Result<(), X11EvidenceError> {
    if snapshot_ts == current_ts {
        Ok(())
    } else {
        Err(X11EvidenceError::InconsistentTimestamp)
    }
}

/// Helper: valid 128-byte EDID block with correct checksum.
pub fn make_valid_edid(seed: u8) -> Vec<u8> {
    let mut block = vec![seed; 128];
    // Adjust last byte so sum % 256 == 0.
    let sum: u16 = block[..127].iter().map(|b| *b as u16).sum();
    block[127] = (256 - (sum % 256)) as u8;
    block
}

#[derive(Debug, Default)]
pub struct X11EvidenceLogic;

/// Ownership anchor: audited `x11rb` leaf is linked on Linux.
#[cfg(target_os = "linux")]
pub fn authorized_x11rb_present() -> bool {
    // Feature surface: randr (and its render closure) only.
    let _ = core::mem::size_of::<x11rb::protocol::randr::Connection>();
    true
}

/// Ownership anchor: optional AT-SPI role lookup over zbus.
#[cfg(target_os = "linux")]
pub fn authorized_atspi_present() -> bool {
    let _ = core::mem::size_of::<atspi::AccessibilityConnection>();
    true
}
