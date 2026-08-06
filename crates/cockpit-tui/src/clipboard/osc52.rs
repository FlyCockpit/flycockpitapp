//! OSC52 emission adapter — selector `c`, single transport, shared total cap.

use std::io::Write;

use base64::Engine;
use cockpit_proto::terminal::OSC52_MAX_SEQUENCE_BYTES;

use super::types::{OscTransport, SafeErrorKind};

/// Fixed envelope length for raw BEL form: `ESC ]` + `52;c;` + BEL = 8 bytes.
pub const OSC52_RAW_ENVELOPE_BYTES: usize = 8;

/// Maximum base64 payload length that still fits the total sequence cap.
#[cfg(test)]
pub fn max_b64_payload_len() -> usize {
    OSC52_MAX_SEQUENCE_BYTES.saturating_sub(OSC52_RAW_ENVELOPE_BYTES)
}

/// Total raw BEL sequence length for a base64 payload (introducer+selector+payload+BEL).
pub fn raw_sequence_len(encoded_b64_len: usize) -> usize {
    OSC52_RAW_ENVELOPE_BYTES + encoded_b64_len
}

/// Build exactly one OSC52 frame for the chosen transport.
///
/// - [`OscTransport::Direct`]: raw `ESC ] 52 ; c ; payload BEL`
/// - [`OscTransport::TmuxPassthrough`]: one DCS-wrapped frame only
///
/// Never concatenates raw and wrapped frames.
pub fn build_sequence(encoded_b64: &str, transport: OscTransport) -> String {
    let raw = format!("\x1b]52;c;{encoded_b64}\x07");
    match transport {
        OscTransport::Direct => raw,
        OscTransport::TmuxPassthrough => {
            // tmux DCS passthrough: `ESC P tmux ;` + ESC-doubled inner + ST.
            let inner = raw.replace('\x1b', "\x1b\x1b");
            format!("\x1bPtmux;{inner}\x1b\\")
        }
    }
}

/// Encode text and reject before any write when the total sequence would
/// exceed [`OSC52_MAX_SEQUENCE_BYTES`].
pub fn encode_checked(text: &str) -> Result<String, SafeErrorKind> {
    if text.is_empty() {
        return Err(SafeErrorKind::Empty);
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    if raw_sequence_len(encoded.len()) > OSC52_MAX_SEQUENCE_BYTES {
        return Err(SafeErrorKind::TooLarge);
    }
    Ok(encoded)
}

/// Largest decoded UTF-8 payload whose STANDARD base64 plus raw envelope
/// is still within the shared total sequence cap.
#[cfg(test)]
pub fn largest_in_cap_decoded_len() -> usize {
    // STANDARD base64 encodes 3 bytes -> 4 chars. Find max n such that
    // raw_sequence_len(base64_len(n)) <= OSC52_MAX_SEQUENCE_BYTES.
    let max_b64 = max_b64_payload_len();
    // Round down to a valid base64 length (multiple of 4).
    let max_b64 = max_b64 - (max_b64 % 4);
    (max_b64 / 4) * 3
}

pub trait Osc52Emitter: Send {
    /// Emit one frame. Returns Ok when bytes were written (Unverified unless
    /// the session advertises acknowledgement).
    fn emit(&mut self, text: &str, transport: OscTransport) -> Result<(), SafeErrorKind>;
}

/// Production emitter that writes to stdout and flushes.
#[derive(Debug, Default)]
pub struct StdoutOsc52Emitter;

impl Osc52Emitter for StdoutOsc52Emitter {
    fn emit(&mut self, text: &str, transport: OscTransport) -> Result<(), SafeErrorKind> {
        let encoded = encode_checked(text)?;
        let seq = build_sequence(&encoded, transport);
        // Defense in depth: never write a sequence over the shared cap.
        if seq.len() > OSC52_MAX_SEQUENCE_BYTES && matches!(transport, OscTransport::Direct) {
            return Err(SafeErrorKind::TooLarge);
        }
        let mut out = std::io::stdout();
        write!(out, "{seq}").map_err(|_| SafeErrorKind::WriteFailed)?;
        out.flush().map_err(|_| SafeErrorKind::WriteFailed)?;
        Ok(())
    }
}

/// Recording emitter for tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct RecordingOsc52Emitter {
    pub frames: Vec<(OscTransport, String)>,
    pub fail: Option<SafeErrorKind>,
}

#[cfg(test)]
impl Osc52Emitter for RecordingOsc52Emitter {
    fn emit(&mut self, text: &str, transport: OscTransport) -> Result<(), SafeErrorKind> {
        if let Some(err) = self.fail {
            return Err(err);
        }
        let encoded = encode_checked(text)?;
        let seq = build_sequence(&encoded, transport);
        self.frames.push((transport, seq));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_proto::terminal::OSC52_MAX_SEQUENCE_BYTES;

    #[test]
    fn direct_frame_is_selector_c_bel() {
        let seq = build_sequence("QUJD", OscTransport::Direct);
        assert_eq!(seq, "\x1b]52;c;QUJD\x07");
        assert_eq!(seq.len(), raw_sequence_len(4));
    }

    #[test]
    fn tmux_passthrough_emits_exactly_one_wrapped_frame() {
        let seq = build_sequence("QUJD", OscTransport::TmuxPassthrough);
        assert_eq!(seq, "\x1bPtmux;\x1b\x1b]52;c;QUJD\x07\x1b\\");
        assert!(!seq.contains("\x07\x07"));
        // Must not concatenate a raw prefix.
        assert!(!seq.starts_with("\x1b]52;"));
    }

    #[test]
    fn encode_rejects_over_total_cap_before_any_payload_write() {
        let n = largest_in_cap_decoded_len() + 3;
        let big = "x".repeat(n);
        assert_eq!(encode_checked(&big), Err(SafeErrorKind::TooLarge));
    }

    #[test]
    fn largest_in_cap_payload_encodes() {
        let n = largest_in_cap_decoded_len();
        let payload = "y".repeat(n);
        let encoded = encode_checked(&payload).expect("in-cap");
        assert!(raw_sequence_len(encoded.len()) <= OSC52_MAX_SEQUENCE_BYTES);
    }
}
