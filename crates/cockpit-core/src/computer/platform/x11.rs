//! X11/RandR target-evidence pure logic.
//!
//! Session identity is a domain hash over the canonical X server endpoint and
//! length-delimited server setup vendor/release. A screen suffix and its root
//! window are deliberately excluded: both are scoped beneath an X server,
//! while XTEST input injection is server-global. Local transport spellings
//! are canonicalized so `:0` and `unix:0` name the same server. Xauthority
//! cookie bytes never enter the identity.

use crate::computer::host_identity::domain_hash;
#[cfg(target_os = "linux")]
use crate::computer::host_identity::{
    HostInstallationId, RealHostIdentityFs, SysHostIdentityRng, load_or_create_host_installation_id,
};
use crate::computer::target::OpaqueWindowId;
#[cfg(target_os = "linux")]
use crate::computer::target::{
    BackendKind, EvidenceSource, FieldEvidence, FocusGenerationReducer, RedactedHint,
    StableApplicationId, TargetEvidenceAdapter, TargetGeometry, TargetIdentityEvidence,
    TargetUnavailableReason, empty_unavailable,
};

/// Encode an X11 window id into the platform-neutral evidence identity.
///
/// X11 window ids are 32-bit; they occupy the first four little-endian bytes
/// and the remainder is zero. Identities that use the full 16 bytes (virtual
/// UUIDs, hashed macOS/Windows handles) are not X11 window ids.
pub fn opaque_x11_window_id(window: u32) -> OpaqueWindowId {
    let mut bytes = [0_u8; 16];
    bytes[..4].copy_from_slice(&window.to_le_bytes());
    OpaqueWindowId::from_bytes(bytes)
}

/// Inverse of [`opaque_x11_window_id`]. `None` when the identity is not an
/// X11 window id, so callers can refuse rather than guess a target.
pub fn x11_window_from_opaque(id: &OpaqueWindowId) -> Option<u32> {
    let bytes = id.as_bytes();
    if bytes[4..].iter().copied().any(|byte| byte != 0) {
        return None;
    }
    Some(u32::from_le_bytes(bytes[..4].try_into().ok()?))
}

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
    // Intentionally omit the Xauthority credential and screen-scoped
    // selectors. The resulting ID is also the server-wide X11 input-arbiter
    // namespace, so screen aliases must never partition it.
    let transport = if parts.transport.is_empty() || parts.transport.eq_ignore_ascii_case("unix") {
        "unix"
    } else {
        &parts.transport
    };
    domain_hash(
        b"cockpit.x11.session.v1",
        &[
            transport.as_bytes(),
            &parts.display_number.to_le_bytes(),
            parts.vendor.as_bytes(),
            &parts.release.to_le_bytes(),
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
        EdidValidation::Valid { .. } => {
            let edid = output.edid.as_deref().expect("validated EDID is present");
            return Ok(domain_hash(
                b"cockpit.x11.output.v1",
                &[
                    &output.screen_index.to_le_bytes(),
                    output.connector_name.as_bytes(),
                    edid,
                ],
            ));
        }
        // Virtual and remote RandR outputs commonly have no EDID.  The
        // connector is still stable within the X server session, which is
        // already independently part of the physical-target key.
        EdidValidation::Missing => {
            return Ok(domain_hash(
                b"cockpit.x11.output-without-edid.v1",
                &[
                    &output.screen_index.to_le_bytes(),
                    output.connector_name.as_bytes(),
                ],
            ));
        }
        EdidValidation::NonIntegralBlockCount | EdidValidation::BadChecksum => {
            return Err(X11EvidenceError::InvalidEdid);
        }
    }
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
    let mut invalid_edid = false;
    for o in outputs {
        // Connected-but-disabled outputs have no active CRTC. They must not
        // poison evidence for the active output containing the focused window.
        if !o.connected || o.crtc_id.is_none() || o.mode_id.is_none() || o.geometry.is_none() {
            continue;
        }
        let id = match stable_output_identity(o) {
            Ok(id) => id,
            Err(X11EvidenceError::InvalidEdid) => {
                // An unrelated malformed EDID is not a reason to reject a
                // working desktop. If it is the focused output, selection
                // below fails closed because that group is absent.
                invalid_edid = true;
                continue;
            }
            Err(error) => return Err(error),
        };
        let (Some(crtc), Some(mode), Some(geom)) = (o.crtc_id, o.mode_id, o.geometry) else {
            unreachable!("active output fields were checked above");
        };
        usable.push((crtc, mode, geom, o.rotation, o.clone_group, id));
    }
    if usable.is_empty() {
        return Err(if invalid_edid {
            X11EvidenceError::InvalidEdid
        } else {
            X11EvidenceError::NoConnectedCrtc
        });
    }

    // Group by (crtc) first, then merge clone-compatible distinct CRTCs.
    let mut groups: Vec<MirrorGroup> = Vec::new();
    let mut used = vec![false; usable.len()];

    for i in 0..usable.len() {
        if used[i] {
            continue;
        }
        used[i] = true;
        let (_, mode_i, geom_i, rot_i, _, id_i) = usable[i];
        let mut ids = vec![id_i];
        let mut members = vec![i];
        let mut changed = true;
        while changed {
            changed = false;
            for j in 0..usable.len() {
                if used[j] {
                    continue;
                }
                let (_, _, _, _, _, id_j) = usable[j];
                let compatible = members.iter().any(|member| {
                    let (crtc_a, mode_a, geom_a, rot_a, clone_a, _) = usable[*member];
                    let (crtc_b, mode_b, geom_b, rot_b, clone_b, _) = usable[j];
                    crtc_a == crtc_b
                        || (mode_a == mode_b
                            && geom_a == geom_b
                            && rot_a == rot_b
                            && clone_a.is_some()
                            && clone_a == clone_b)
                });
                if compatible {
                    used[j] = true;
                    members.push(j);
                    ids.push(id_j);
                    changed = true;
                }
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

/// Production target-evidence adapter for the X11 desktop selected by
/// `DISPLAY`. Each snapshot is queried synchronously from one X server
/// connection so the focused window and RandR resources share one request
/// ordering boundary.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct X11TargetEvidenceAdapter {
    display: String,
    host: HostInstallationId,
    reducer: FocusGenerationReducer,
    observed_epoch: u64,
}

#[cfg(target_os = "linux")]
impl X11TargetEvidenceAdapter {
    pub fn new(display: impl Into<String>) -> Result<Self, TargetUnavailableReason> {
        let display = display.into();
        if display.trim().is_empty() {
            return Err(TargetUnavailableReason::UnsupportedPlatform);
        }
        let data_dir = crate::config::resolve::cockpit_data_dir()
            .map_err(|_| TargetUnavailableReason::HostIdentityUnavailable)?;
        let host = load_or_create_host_installation_id(
            &data_dir,
            &mut SysHostIdentityRng,
            &mut RealHostIdentityFs,
        )
        .map_err(|_| TargetUnavailableReason::HostIdentityUnavailable)?;
        Ok(Self {
            display,
            host,
            reducer: FocusGenerationReducer::new(),
            observed_epoch: 0,
        })
    }

    fn capture_x11_snapshot(&self) -> Result<TargetIdentityEvidence, TargetUnavailableReason> {
        use x11rb::connection::Connection as _;
        use x11rb::protocol::randr::{Connection as RandrConnection, ConnectionExt as _};
        use x11rb::protocol::xproto::{AtomEnum, ConnectionExt as _};

        fn unavailable<T>(_: T) -> TargetUnavailableReason {
            TargetUnavailableReason::MissingCapability
        }
        let (connection, screen_index) =
            x11rb::connect(Some(&self.display)).map_err(unavailable)?;
        let setup = connection.setup();
        let screen = setup
            .roots
            .get(screen_index)
            .ok_or(TargetUnavailableReason::MissingCapability)?;
        let root = screen.root;
        let root_geometry = connection
            .get_geometry(root)
            .map_err(unavailable)?
            .reply()
            .map_err(unavailable)?;

        let randr_version = connection
            .randr_query_version(1, 3)
            .map_err(unavailable)?
            .reply()
            .map_err(unavailable)?;
        check_randr_version(randr_version.major_version, randr_version.minor_version)
            .map_err(map_evidence_error)?;

        let active_window_atom = connection
            .intern_atom(false, b"_NET_ACTIVE_WINDOW")
            .map_err(unavailable)?
            .reply()
            .map_err(unavailable)?
            .atom;
        let active_window_reply = connection
            .get_property(false, root, active_window_atom, AtomEnum::WINDOW, 0, 1)
            .map_err(unavailable)?
            .reply()
            .map_err(unavailable)?;
        let active_window = active_window_reply
            .value32()
            .and_then(|mut values| values.next())
            .filter(|window| *window != x11rb::NONE)
            .ok_or(TargetUnavailableReason::FocusIdentityUnavailable)?;

        let window_geometry = connection
            .get_geometry(active_window)
            .map_err(unavailable)?
            .reply()
            .map_err(unavailable)?;
        let translated = connection
            .translate_coordinates(active_window, root, 0, 0)
            .map_err(unavailable)?
            .reply()
            .map_err(unavailable)?;
        let focused_geometry = FocusedWindowGeom {
            x: translated.dst_x,
            y: translated.dst_y,
            w: window_geometry.width,
            h: window_geometry.height,
        };

        let edid_atom = connection
            .intern_atom(false, b"EDID")
            .map_err(unavailable)?
            .reply()
            .map_err(unavailable)?
            .atom;
        let resources = connection
            .randr_get_screen_resources_current(root)
            .map_err(unavailable)?
            .reply()
            .map_err(unavailable)?;
        let mut outputs = Vec::with_capacity(resources.outputs.len());
        let mut output_clone_peers = Vec::with_capacity(resources.outputs.len());
        for output in &resources.outputs {
            let info = connection
                .randr_get_output_info(*output, resources.config_timestamp)
                .map_err(unavailable)?
                .reply()
                .map_err(unavailable)?;
            check_resource_timestamp(info.timestamp, resources.config_timestamp)
                .map_err(map_evidence_error)?;
            let connected = info.connection == RandrConnection::CONNECTED;
            let crtc = (info.crtc != x11rb::NONE).then_some(info.crtc);
            let crtc_info = if let Some(crtc) = crtc {
                let reply = connection
                    .randr_get_crtc_info(crtc, resources.config_timestamp)
                    .map_err(unavailable)?
                    .reply()
                    .map_err(unavailable)?;
                check_resource_timestamp(reply.timestamp, resources.config_timestamp)
                    .map_err(map_evidence_error)?;
                Some(reply)
            } else {
                None
            };
            let edid_reply = connection
                .randr_get_output_property(*output, edid_atom, AtomEnum::ANY, 0, 256, false, false)
                .map_err(unavailable)?
                .reply()
                .map_err(unavailable)?;
            let edid = (edid_reply.format == 8
                && edid_reply.bytes_after == 0
                && !edid_reply.data.is_empty())
            .then_some(edid_reply.data);
            output_clone_peers.push(info.clones.clone());
            outputs.push(RandrOutputSnapshot {
                screen_index: screen_index as u32,
                connector_name: String::from_utf8_lossy(&info.name).into_owned(),
                edid,
                crtc_id: crtc,
                mode_id: crtc_info
                    .as_ref()
                    .and_then(|reply| (reply.mode != x11rb::NONE).then_some(reply.mode)),
                geometry: crtc_info
                    .as_ref()
                    .map(|reply| (reply.x, reply.y, reply.width, reply.height)),
                rotation: crtc_info
                    .as_ref()
                    .map_or(0, |reply| u16::from(reply.rotation)),
                connected,
                clone_group: None,
            });
        }
        assign_production_clone_groups(&mut outputs, &resources.outputs, &output_clone_peers);
        let groups = build_mirror_groups(&outputs).map_err(map_evidence_error)?;
        let focused_group =
            select_mirror_group(&groups, focused_geometry).map_err(map_evidence_error)?;

        let (transport, display_number, screen_number) =
            parse_display_identity(&self.display, screen_index as u32)
                .ok_or(TargetUnavailableReason::MissingCapability)?;
        let session = x11_session_or_seat_id(&X11SessionParts {
            transport,
            display_number,
            screen: screen_number,
            vendor: String::from_utf8_lossy(&setup.vendor).into_owned(),
            release: setup.release_number,
            root_window_id: root,
            xauthority_cookie: Vec::new(),
        });

        let pid_atom = connection
            .intern_atom(false, b"_NET_WM_PID")
            .map_err(unavailable)?
            .reply()
            .map_err(unavailable)?
            .atom;
        let process_id = connection
            .get_property(false, active_window, pid_atom, AtomEnum::CARDINAL, 0, 1)
            .ok()
            .and_then(|cookie| cookie.reply().ok())
            .and_then(|reply| reply.value32().and_then(|mut values| values.next()));
        let title = x11_text_property(&connection, active_window, b"_NET_WM_NAME");
        let class = x11_text_property(&connection, active_window, b"WM_CLASS");

        // Close the synchronous-query bracket: neither focus nor the RandR
        // configuration may have changed while the component fields above
        // were assembled into one snapshot.
        let resources_after = connection
            .randr_get_screen_resources_current(root)
            .map_err(unavailable)?
            .reply()
            .map_err(unavailable)?;
        if resources_after.config_timestamp != resources.config_timestamp {
            return Err(TargetUnavailableReason::StaleTarget);
        }
        let root_geometry_after = connection
            .get_geometry(root)
            .map_err(unavailable)?
            .reply()
            .map_err(unavailable)?;
        if root_geometry_after.x != root_geometry.x
            || root_geometry_after.y != root_geometry.y
            || root_geometry_after.width != root_geometry.width
            || root_geometry_after.height != root_geometry.height
        {
            return Err(TargetUnavailableReason::StaleTarget);
        }
        let active_window_after = connection
            .get_property(false, root, active_window_atom, AtomEnum::WINDOW, 0, 1)
            .map_err(unavailable)?
            .reply()
            .map_err(unavailable)?
            .value32()
            .and_then(|mut values| values.next());
        if active_window_after != Some(active_window) {
            return Err(TargetUnavailableReason::QueryMismatch);
        }

        let mut snapshot = empty_unavailable(BackendKind::RealDesktopX11);
        snapshot.host_installation_id =
            FieldEvidence::available(self.host, EvidenceSource::X11ServerSetup);
        snapshot.platform_session_or_seat_id =
            FieldEvidence::available(session, EvidenceSource::X11ServerSetup);
        snapshot.physical_display_id = FieldEvidence::available(
            focused_group.physical_display_id(),
            EvidenceSource::X11Randr,
        );
        snapshot.focused_window_id = FieldEvidence::available(
            opaque_x11_window_id(active_window),
            EvidenceSource::X11NetActiveWindow,
        );
        snapshot.process_id = process_id.map_or_else(
            || {
                FieldEvidence::unavailable(
                    TargetUnavailableReason::PartialEvidence,
                    Some(EvidenceSource::X11NetActiveWindow),
                )
            },
            |pid| FieldEvidence::available(pid, EvidenceSource::X11NetActiveWindow),
        );
        snapshot.stable_application_id = FieldEvidence::<StableApplicationId>::unavailable(
            TargetUnavailableReason::PartialEvidence,
            Some(EvidenceSource::X11NetActiveWindow),
        );
        // AT-SPI is not wired. Leave widget role/subrole unavailable so
        // TypeText fail-closes as Credential (issue #290) rather than
        // substituting the focused window's WM_CLASS as field context.
        snapshot.accessibility_role = FieldEvidence::unavailable(
            TargetUnavailableReason::PartialEvidence,
            Some(EvidenceSource::AtSpi),
        );
        snapshot.accessibility_subrole = FieldEvidence::unavailable(
            TargetUnavailableReason::PartialEvidence,
            Some(EvidenceSource::AtSpi),
        );
        snapshot.title_hint = title.map_or_else(
            || {
                FieldEvidence::unavailable(
                    TargetUnavailableReason::PartialEvidence,
                    Some(EvidenceSource::X11NetActiveWindow),
                )
            },
            |value| {
                FieldEvidence::available(
                    RedactedHint::from_raw(&value),
                    EvidenceSource::X11NetActiveWindow,
                )
            },
        );
        snapshot.class_hint = class.map_or_else(
            || {
                FieldEvidence::unavailable(
                    TargetUnavailableReason::PartialEvidence,
                    Some(EvidenceSource::X11NetActiveWindow),
                )
            },
            |value| {
                FieldEvidence::available(
                    RedactedHint::from_raw(&value),
                    EvidenceSource::X11NetActiveWindow,
                )
            },
        );
        snapshot.geometry = FieldEvidence::available(
            TargetGeometry {
                x: i32::from(focused_geometry.x),
                y: i32::from(focused_geometry.y),
                width: u32::from(focused_geometry.w),
                height: u32::from(focused_geometry.h),
                scale: 1.0,
            },
            EvidenceSource::X11NetActiveWindow,
        );
        snapshot.desktop_geometry = FieldEvidence::available(
            TargetGeometry {
                x: i32::from(root_geometry.x),
                y: i32::from(root_geometry.y),
                width: u32::from(root_geometry.width),
                height: u32::from(root_geometry.height),
                scale: 1.0,
            },
            EvidenceSource::X11Randr,
        );
        snapshot.synchronous_recheck = true;
        Ok(snapshot)
    }
}

/// Populate the pure-logic clone token from RandR's production `clones`
/// output IDs. RandR reports a graph, so every connected component receives
/// its smallest output ID as a deterministic token.
#[cfg(target_os = "linux")]
fn assign_production_clone_groups(
    outputs: &mut [RandrOutputSnapshot],
    output_ids: &[u32],
    output_clone_peers: &[Vec<u32>],
) {
    let mut peers = std::collections::HashMap::<u32, Vec<u32>>::new();
    for (output, clones) in output_ids.iter().zip(output_clone_peers) {
        peers.entry(*output).or_default().extend(clones);
    }
    for (index, output) in outputs.iter_mut().enumerate() {
        let output_id = output_ids[index];
        let mut seen = std::collections::BTreeSet::from([output_id]);
        let mut pending = vec![output_id];
        while let Some(current) = pending.pop() {
            for (candidate, candidate_peers) in &peers {
                if (*candidate == current || candidate_peers.contains(&current))
                    && seen.insert(*candidate)
                {
                    pending.push(*candidate);
                }
                if *candidate == current {
                    for peer in candidate_peers {
                        if seen.insert(*peer) {
                            pending.push(*peer);
                        }
                    }
                }
            }
        }
        output.clone_group = (seen.len() > 1).then(|| *seen.first().expect("non-empty clone set"));
    }
}

#[cfg(target_os = "linux")]
impl TargetEvidenceAdapter for X11TargetEvidenceAdapter {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::RealDesktopX11
    }

    fn capture_snapshot(&mut self) -> Result<TargetIdentityEvidence, TargetUnavailableReason> {
        let mut snapshot = self.capture_x11_snapshot()?;
        self.observed_epoch = self
            .observed_epoch
            .checked_add(1)
            .ok_or(TargetUnavailableReason::EpochOverflow)?;
        snapshot.adapter_observed_epoch = self.observed_epoch;
        snapshot.focus_generation = self.reducer.observe(&snapshot)?;
        Ok(snapshot)
    }

    fn observed_focus_epoch(&self) -> u64 {
        self.observed_epoch
    }
}

#[cfg(target_os = "linux")]
fn x11_text_property(
    connection: &x11rb::rust_connection::RustConnection,
    window: u32,
    name: &[u8],
) -> Option<String> {
    use x11rb::protocol::xproto::{AtomEnum, ConnectionExt as _};

    let atom = connection.intern_atom(true, name).ok()?.reply().ok()?.atom;
    if atom == x11rb::NONE {
        return None;
    }
    let reply = connection
        .get_property(false, window, atom, AtomEnum::ANY, 0, 256)
        .ok()?
        .reply()
        .ok()?;
    let value = reply
        .value
        .split(|byte| *byte == 0)
        .find(|part| !part.is_empty())?;
    Some(String::from_utf8_lossy(value).into_owned())
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_display_identity(
    display: &str,
    default_screen: u32,
) -> Option<(String, u32, u32)> {
    let (transport, display_and_screen) = display.rsplit_once(':')?;
    let (display_number, screen) = display_and_screen
        .split_once('.')
        .map_or((display_and_screen, None), |(display, screen)| {
            (display, Some(screen))
        });
    Some((
        if transport.is_empty() || transport.eq_ignore_ascii_case("unix") {
            "unix".to_string()
        } else {
            transport.to_string()
        },
        display_number.parse().ok()?,
        match screen {
            Some(value) => value.parse().ok()?,
            None => default_screen,
        },
    ))
}

/// Canonical identity of an X server, independent of local transport aliases
/// and the optional screen suffix. X11 input injection is server-global.
#[cfg(target_os = "linux")]
pub(crate) fn canonical_x11_server_identity(display: &str) -> Option<(String, u32)> {
    parse_display_identity(display, 0)
        .map(|(transport, display_number, _)| (transport, display_number))
}

#[cfg(target_os = "linux")]
fn map_evidence_error(error: X11EvidenceError) -> TargetUnavailableReason {
    match error {
        X11EvidenceError::AmbiguousOutput => TargetUnavailableReason::AmbiguousOutput,
        X11EvidenceError::MissingActiveWindow => TargetUnavailableReason::FocusIdentityUnavailable,
        X11EvidenceError::InconsistentTimestamp => TargetUnavailableReason::StaleTarget,
        X11EvidenceError::RandrVersionTooOld | X11EvidenceError::MissingRandr => {
            TargetUnavailableReason::MissingCapability
        }
        X11EvidenceError::Unauthenticated => TargetUnavailableReason::PermissionDenied,
        X11EvidenceError::MissingGeometry
        | X11EvidenceError::InvalidEdid
        | X11EvidenceError::NoConnectedCrtc
        | X11EvidenceError::NoMode
        | X11EvidenceError::NoIntersectingGroup => TargetUnavailableReason::PartialEvidence,
    }
}

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

#[cfg(test)]
mod opaque_window_tests {
    use super::{opaque_x11_window_id, x11_window_from_opaque};
    use crate::computer::target::OpaqueWindowId;

    #[test]
    fn x11_window_id_round_trips_and_rejects_non_x11_identities() {
        let id = opaque_x11_window_id(0x00ab_cdef);
        assert_eq!(x11_window_from_opaque(&id), Some(0x00ab_cdef));
        assert_eq!(
            x11_window_from_opaque(&OpaqueWindowId::from_bytes([0xAA; 16])),
            None
        );
        assert_eq!(x11_window_from_opaque(&opaque_x11_window_id(0)), Some(0));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod production_adapter_tests {
    use super::{
        RandrOutputSnapshot, X11SessionParts, assign_production_clone_groups,
        canonical_x11_server_identity, parse_display_identity, x11_session_or_seat_id,
    };

    #[test]
    fn display_identity_parses_local_remote_and_default_screen() {
        assert_eq!(
            parse_display_identity(":0", 2),
            Some(("unix".to_string(), 0, 2))
        );
        assert_eq!(
            parse_display_identity("workstation.example:7.1", 0),
            Some(("workstation.example".to_string(), 7, 1))
        );
        assert_eq!(
            parse_display_identity("[::1]:3.0", 4),
            Some(("[::1]".to_string(), 3, 0))
        );
    }

    #[test]
    fn display_identity_rejects_malformed_numbers() {
        assert_eq!(parse_display_identity(":desktop", 0), None);
        assert_eq!(parse_display_identity(":0.screen", 0), None);
        assert_eq!(parse_display_identity("missing-colon", 0), None);
    }

    #[test]
    fn canonical_server_identity_unifies_local_aliases_and_screens() {
        assert_eq!(
            canonical_x11_server_identity(":0"),
            canonical_x11_server_identity("unix:0")
        );
        assert_eq!(
            canonical_x11_server_identity(":0.1"),
            canonical_x11_server_identity(":0.0")
        );
        assert_ne!(
            canonical_x11_server_identity(":0"),
            canonical_x11_server_identity(":1")
        );
    }

    #[test]
    fn local_display_aliases_share_one_session_identity() {
        let parts = |transport: &str| X11SessionParts {
            transport: transport.to_string(),
            display_number: 0,
            screen: 0,
            vendor: "X.Org".to_string(),
            release: 1,
            root_window_id: 42,
            xauthority_cookie: Vec::new(),
        };
        assert_eq!(
            x11_session_or_seat_id(&parts("")),
            x11_session_or_seat_id(&parts("unix"))
        );
    }

    #[test]
    fn screen_scoped_selectors_share_one_session_identity() {
        let server = |screen, root_window_id| X11SessionParts {
            transport: "unix".to_string(),
            display_number: 0,
            screen,
            vendor: "X.Org".to_string(),
            release: 1,
            root_window_id,
            xauthority_cookie: Vec::new(),
        };

        // `:0.0` and `:0.1` select different screen roots, but xdotool's
        // XTEST keyboard/pointer injection remains global to the X server.
        assert_eq!(
            x11_session_or_seat_id(&server(0, 42)),
            x11_session_or_seat_id(&server(1, 99))
        );
    }

    #[test]
    fn randr_clone_output_ids_reach_mirror_group_logic() {
        let output = |name: &str| RandrOutputSnapshot {
            screen_index: 0,
            connector_name: name.to_string(),
            edid: None,
            crtc_id: Some(1),
            mode_id: Some(1),
            geometry: Some((0, 0, 1280, 720)),
            rotation: 0,
            connected: true,
            clone_group: None,
        };
        let mut outputs = vec![output("DP-1"), output("HDMI-1")];
        assign_production_clone_groups(&mut outputs, &[10, 20], &[vec![20], vec![10]]);
        assert_eq!(outputs[0].clone_group, outputs[1].clone_group);
        assert!(outputs[0].clone_group.is_some());
    }
}
