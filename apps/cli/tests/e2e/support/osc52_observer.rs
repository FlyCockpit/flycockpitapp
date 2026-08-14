//! Bounded OSC52 observer for PTY conformance tests.
//!
//! Recognizes Direct (`ESC ] 52 ; <sel> ; <b64> BEL`) and tmux-passthrough
//! (`ESC P tmux ;` + ESC-doubled inner + `ESC \`) envelopes. Reports only
//! metadata: frame count, selector, decoded byte length, and SHA-256.
//! Clipboard plaintext is never stored, printed, logged, or written to disk.

use std::fmt;

use cockpit_proto::terminal::OSC52_MAX_SEQUENCE_BYTES;
use sha2::{Digest, Sha256};

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;
const TMUX_INTRO: &[u8] = b"\x1bPtmux;";
const OSC52_INTRO: &[u8] = b"\x1b]52;";
const ST: &[u8] = b"\x1b\\";
/// Ring-buffer cap for retained metadata. `frame_count` still tracks every
/// accepted frame so dependents can observe deltas without unbounded growth.
const MAX_RETAINED_FRAMES: usize = 32;

/// Metadata retained for one recognized OSC52 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Osc52FrameMeta {
    pub selector: char,
    pub decoded_len: usize,
    pub sha256: String,
}

/// Bounded scanner that extracts OSC52 metadata from a terminal byte stream.
#[derive(Clone)]
pub struct Osc52Observer {
    frames: Vec<Osc52FrameMeta>,
    accepted_frames: usize,
    dropped_frames: usize,
    rejected_incomplete: usize,
    rejected_over_limit: usize,
    pending: Vec<u8>,
    state: ScanState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanState {
    Normal,
    Esc,
    Osc52,
    Tmux,
}

impl Default for Osc52Observer {
    fn default() -> Self {
        Self::new()
    }
}

impl Osc52Observer {
    pub fn new() -> Self {
        Self {
            frames: Vec::new(),
            accepted_frames: 0,
            dropped_frames: 0,
            rejected_incomplete: 0,
            rejected_over_limit: 0,
            pending: Vec::new(),
            state: ScanState::Normal,
        }
    }

    pub fn frames(&self) -> &[Osc52FrameMeta] {
        &self.frames
    }

    /// Total accepted frames, including those dropped from the metadata ring.
    pub fn frame_count(&self) -> usize {
        self.accepted_frames
    }

    pub fn dropped_frames(&self) -> usize {
        self.dropped_frames
    }

    pub fn rejected_incomplete(&self) -> usize {
        self.rejected_incomplete
    }

    pub fn rejected_over_limit(&self) -> usize {
        self.rejected_over_limit
    }

    /// Feed a chunk of terminal output. Incomplete frames stay in a buffer
    /// bounded by [`OSC52_MAX_SEQUENCE_BYTES`].
    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.push_byte(b);
        }
    }

    /// Reject any in-progress frame as incomplete. Call at stream end.
    pub fn finish(&mut self) {
        if !self.pending.is_empty() || !matches!(self.state, ScanState::Normal) {
            self.reject_incomplete();
        }
    }

    fn push_byte(&mut self, b: u8) {
        match self.state {
            ScanState::Normal => {
                if b == ESC {
                    self.pending.clear();
                    self.pending.push(b);
                    self.state = ScanState::Esc;
                }
            }
            ScanState::Esc => {
                if !self.push_pending(b) {
                    return;
                }
                if self.pending == OSC52_INTRO {
                    self.state = ScanState::Osc52;
                } else if self.pending == TMUX_INTRO {
                    self.state = ScanState::Tmux;
                } else if !OSC52_INTRO.starts_with(&self.pending)
                    && !TMUX_INTRO.starts_with(&self.pending)
                {
                    self.reset_scan();
                }
            }
            ScanState::Osc52 => {
                if !self.push_pending(b) {
                    return;
                }
                if b == BEL || self.pending.ends_with(ST) {
                    self.complete_direct();
                }
            }
            ScanState::Tmux => {
                if !self.push_pending(b) {
                    return;
                }
                if self.pending.ends_with(ST) {
                    self.complete_tmux();
                }
            }
        }
    }

    fn push_pending(&mut self, b: u8) -> bool {
        if self.pending.len() >= OSC52_MAX_SEQUENCE_BYTES {
            self.reject_over_limit();
            return false;
        }
        self.pending.push(b);
        true
    }

    fn complete_direct(&mut self) {
        let seq = std::mem::take(&mut self.pending);
        match parse_direct_osc52(&seq) {
            Some(meta) => self.push_frame(meta),
            None => self.rejected_incomplete += 1,
        }
        self.state = ScanState::Normal;
    }

    fn complete_tmux(&mut self) {
        let seq = std::mem::take(&mut self.pending);
        match parse_tmux_osc52(&seq) {
            Some(meta) => self.push_frame(meta),
            None => self.rejected_incomplete += 1,
        }
        self.state = ScanState::Normal;
    }

    fn push_frame(&mut self, meta: Osc52FrameMeta) {
        self.accepted_frames += 1;
        if self.frames.len() == MAX_RETAINED_FRAMES {
            self.frames.remove(0);
            self.dropped_frames += 1;
        }
        self.frames.push(meta);
    }

    fn reject_incomplete(&mut self) {
        self.rejected_incomplete += 1;
        self.reset_scan();
    }

    fn reject_over_limit(&mut self) {
        self.rejected_over_limit += 1;
        self.reset_scan();
    }

    fn reset_scan(&mut self) {
        self.pending.clear();
        // Bound capacity so a rejected over-limit stream cannot grow the
        // buffer on subsequent pushes of the same frame.
        self.pending.shrink_to(0);
        self.state = ScanState::Normal;
    }
}

impl fmt::Debug for Osc52Observer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Osc52Observer")
            .field("frame_count", &self.accepted_frames)
            .field("retained_frames", &self.frames.len())
            .field("dropped_frames", &self.dropped_frames)
            .field("frames", &self.frames)
            .field("rejected_incomplete", &self.rejected_incomplete)
            .field("rejected_over_limit", &self.rejected_over_limit)
            .field("pending_bytes", &self.pending.len())
            .finish()
    }
}

fn parse_direct_osc52(seq: &[u8]) -> Option<Osc52FrameMeta> {
    let body = seq.strip_prefix(OSC52_INTRO)?;
    let body = if let Some(stripped) = body.strip_suffix(&[BEL]) {
        stripped
    } else {
        body.strip_suffix(ST)?
    };
    parse_selector_and_payload(body)
}

fn parse_tmux_osc52(seq: &[u8]) -> Option<Osc52FrameMeta> {
    let rest = seq.strip_prefix(TMUX_INTRO)?;
    let inner_wrapped = rest.strip_suffix(ST)?;
    let mut inner = Vec::with_capacity(inner_wrapped.len());
    let mut i = 0;
    while i < inner_wrapped.len() {
        if inner_wrapped[i] == ESC && inner_wrapped.get(i + 1) == Some(&ESC) {
            inner.push(ESC);
            i += 2;
        } else {
            inner.push(inner_wrapped[i]);
            i += 1;
        }
    }
    parse_direct_osc52(&inner)
}

fn parse_selector_and_payload(body: &[u8]) -> Option<Osc52FrameMeta> {
    let semi = body.iter().position(|&b| b == b';')?;
    let selector_bytes = &body[..semi];
    let payload = &body[semi + 1..];
    if selector_bytes.len() != 1 || !selector_bytes[0].is_ascii() {
        return None;
    }
    let selector = selector_bytes[0] as char;
    let (decoded_len, sha256) = digest_base64_streaming(payload)?;
    Some(Osc52FrameMeta {
        selector,
        decoded_len,
        sha256,
    })
}

/// Decode STANDARD base64 in 4-character blocks into a 3-byte stack buffer,
/// feeding SHA-256 and a length counter. The decoded payload is never stored.
fn digest_base64_streaming(input: &[u8]) -> Option<(usize, String)> {
    use base64::Engine;
    if input.is_empty() || input.len() % 4 != 0 {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut decoded_len = 0usize;
    for chunk in input.chunks(4) {
        let mut out = [0u8; 3];
        let n = base64::engine::general_purpose::STANDARD
            .decode_slice(chunk, &mut out)
            .ok()?;
        hasher.update(&out[..n]);
        decoded_len += n;
    }
    Some((decoded_len, hex_sha256_digest(hasher.finalize().as_slice())))
}

fn hex_sha256_digest(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex_sha256_digest(Sha256::digest(bytes).as_slice())
}

/// Build a Direct OSC52 envelope for observer tests. The payload bytes are
/// consumed only to produce the wire frame; callers must not log them.
pub fn direct_osc52_frame(selector: char, payload: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let mut frame = OSC52_INTRO.to_vec();
    frame.push(selector as u8);
    frame.push(b';');
    frame.extend_from_slice(b64.as_bytes());
    frame.push(BEL);
    frame
}

/// Build a tmux-passthrough OSC52 envelope for observer tests.
pub fn tmux_osc52_frame(selector: char, payload: &[u8]) -> Vec<u8> {
    let inner = direct_osc52_frame(selector, payload);
    let mut out = TMUX_INTRO.to_vec();
    for b in inner {
        if b == ESC {
            out.push(ESC);
        }
        out.push(b);
    }
    out.extend_from_slice(ST);
    out
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_sha256(bytes)
}
