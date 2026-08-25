//! The closed binary frame contract for the Unix peer-authenticated leak-reveal
//! socket. One request/response exchange per connection; network byte order.
//! These encode/decode helpers are the **single** wire writers/readers — both
//! the daemon accept loop and the TUI client connect path use them, so the two
//! ends can never drift. The in-process caller does **not** use these frames
//! (it calls the consumption core directly).
//!
//! Request (client → daemon), 67 bytes exactly:
//! ```text
//! version:u8 = 1 | capability_len:u16 (== 64) | capability_hex: [64] ASCII
//! ```
//! Response (daemon → client), status-tagged:
//! ```text
//! version:u8 = 1 | status:u8
//!   status == 0 (Ok): report_id_len:u16 | report_id_utf8
//!                     | generation:u64 | plaintext_len:u32 | plaintext_utf8
//!   status in 1..=4: no body
//! ```
//! No report id, session id, or "binding" field ever appears on the request —
//! the server-side single-slot capability already binds `report_id` + expiry.

use zeroize::Zeroizing;

use crate::daemon::leak_reveal::LeakRevealDenied;
use crate::daemon::proto::LeakRevealToken;
use crate::leaks::LEAK_REVEAL_MAX_PLAINTEXT_BYTES;

/// Frame protocol version.
pub const LEAK_REVEAL_FRAME_VERSION: u8 = 1;

/// The capability hex length carried on the request (32 raw token bytes).
pub const LEAK_REVEAL_CAPABILITY_HEX_LEN: usize = 64;

/// Exact request frame size: `1 + 2 + 64`.
pub const LEAK_REVEAL_REQUEST_FRAME_LEN: usize = 1 + 2 + LEAK_REVEAL_CAPABILITY_HEX_LEN;

/// Max report-id length accepted on the response (oversize → `Internal`).
pub const LEAK_REVEAL_MAX_REPORT_ID_LEN: usize = 512;

/// A structurally invalid frame. Callers close with no content on any of these
/// (never a distinct oracle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameError;

/// The parsed reveal request. The capability token alone is the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakRevealSocketRequest {
    /// Exactly 64 ASCII hex chars (validated structurally; hex/token validity is
    /// the consumption core's constant-time job).
    pub capability_hex: LeakRevealToken,
}

/// The status-tagged reveal response.
pub enum LeakRevealSocketResponse {
    Ok {
        report_id: String,
        generation: u64,
        plaintext: Zeroizing<String>,
    },
    Denied(LeakRevealDenied),
}

fn denied_status(d: LeakRevealDenied) -> u8 {
    match d {
        LeakRevealDenied::Unauthorized => 1,
        LeakRevealDenied::RateLimited => 2,
        LeakRevealDenied::UnavailablePlatform => 3,
        LeakRevealDenied::Internal => 4,
    }
}

fn status_denied(status: u8) -> Option<LeakRevealDenied> {
    match status {
        1 => Some(LeakRevealDenied::Unauthorized),
        2 => Some(LeakRevealDenied::RateLimited),
        3 => Some(LeakRevealDenied::UnavailablePlatform),
        4 => Some(LeakRevealDenied::Internal),
        _ => None,
    }
}

/// Encode a reveal request. `capability_hex` must be exactly 64 chars.
pub fn encode_request(req: &LeakRevealSocketRequest) -> Result<Vec<u8>, FrameError> {
    if req.capability_hex.len() != LEAK_REVEAL_CAPABILITY_HEX_LEN {
        return Err(FrameError);
    }
    let mut buf = Vec::with_capacity(LEAK_REVEAL_REQUEST_FRAME_LEN);
    buf.push(LEAK_REVEAL_FRAME_VERSION);
    buf.extend_from_slice(&(LEAK_REVEAL_CAPABILITY_HEX_LEN as u16).to_be_bytes());
    buf.extend_from_slice(req.capability_hex.as_str().as_bytes());
    Ok(buf)
}

/// Decode a reveal request. Rejects wrong version, `capability_len != 64`,
/// non-ASCII payload, and trailing bytes.
pub fn decode_request(buf: &[u8]) -> Result<LeakRevealSocketRequest, FrameError> {
    if buf.len() != LEAK_REVEAL_REQUEST_FRAME_LEN {
        return Err(FrameError);
    }
    if buf[0] != LEAK_REVEAL_FRAME_VERSION {
        return Err(FrameError);
    }
    let cap_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
    if cap_len != LEAK_REVEAL_CAPABILITY_HEX_LEN {
        return Err(FrameError);
    }
    let hex_bytes = &buf[3..];
    if !hex_bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(FrameError);
    }
    let capability_hex = String::from_utf8(hex_bytes.to_vec()).map_err(|_| FrameError)?;
    Ok(LeakRevealSocketRequest {
        capability_hex: LeakRevealToken::new(capability_hex),
    })
}

/// Encode a reveal response. An `Ok` whose report id or plaintext exceeds its
/// bound is re-encoded as `Internal` (never truncated).
pub fn encode_response(resp: &LeakRevealSocketResponse) -> Vec<u8> {
    match resp {
        LeakRevealSocketResponse::Ok {
            report_id,
            generation,
            plaintext,
        } => {
            if report_id.len() > LEAK_REVEAL_MAX_REPORT_ID_LEN
                || plaintext.len() > LEAK_REVEAL_MAX_PLAINTEXT_BYTES
            {
                return encode_response(&LeakRevealSocketResponse::Denied(
                    LeakRevealDenied::Internal,
                ));
            }
            let mut buf = Vec::new();
            buf.push(LEAK_REVEAL_FRAME_VERSION);
            buf.push(0); // Ok
            buf.extend_from_slice(&(report_id.len() as u16).to_be_bytes());
            buf.extend_from_slice(report_id.as_bytes());
            buf.extend_from_slice(&generation.to_be_bytes());
            buf.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
            buf.extend_from_slice(plaintext.as_bytes());
            buf
        }
        LeakRevealSocketResponse::Denied(d) => {
            vec![LEAK_REVEAL_FRAME_VERSION, denied_status(*d)]
        }
    }
}

/// Decode a reveal response. Rejects wrong version, oversize report id/plaintext,
/// short frames, and trailing bytes. An unknown status is treated as a failure
/// (`Internal`) so the client never installs plaintext.
pub fn decode_response(buf: &[u8]) -> Result<LeakRevealSocketResponse, FrameError> {
    if buf.len() < 2 || buf[0] != LEAK_REVEAL_FRAME_VERSION {
        return Err(FrameError);
    }
    let status = buf[1];
    if status != 0 {
        return Ok(LeakRevealSocketResponse::Denied(
            status_denied(status).unwrap_or(LeakRevealDenied::Internal),
        ));
    }
    // Ok body.
    let mut pos = 2usize;
    let read_u16 = |buf: &[u8], pos: &mut usize| -> Result<usize, FrameError> {
        let end = pos.checked_add(2).ok_or(FrameError)?;
        let slice = buf.get(*pos..end).ok_or(FrameError)?;
        *pos = end;
        Ok(u16::from_be_bytes([slice[0], slice[1]]) as usize)
    };
    let report_id_len = read_u16(buf, &mut pos)?;
    if report_id_len > LEAK_REVEAL_MAX_REPORT_ID_LEN {
        return Err(FrameError);
    }
    let rid_end = pos.checked_add(report_id_len).ok_or(FrameError)?;
    let report_id = String::from_utf8(buf.get(pos..rid_end).ok_or(FrameError)?.to_vec())
        .map_err(|_| FrameError)?;
    pos = rid_end;
    let gen_end = pos.checked_add(8).ok_or(FrameError)?;
    let gen_slice = buf.get(pos..gen_end).ok_or(FrameError)?;
    let generation = u64::from_be_bytes(gen_slice.try_into().map_err(|_| FrameError)?);
    pos = gen_end;
    let pt_len_end = pos.checked_add(4).ok_or(FrameError)?;
    let pt_len_slice = buf.get(pos..pt_len_end).ok_or(FrameError)?;
    let plaintext_len =
        u32::from_be_bytes(pt_len_slice.try_into().map_err(|_| FrameError)?) as usize;
    pos = pt_len_end;
    if plaintext_len > LEAK_REVEAL_MAX_PLAINTEXT_BYTES {
        return Err(FrameError);
    }
    let pt_end = pos.checked_add(plaintext_len).ok_or(FrameError)?;
    let plaintext = Zeroizing::new(
        String::from_utf8(buf.get(pos..pt_end).ok_or(FrameError)?.to_vec())
            .map_err(|_| FrameError)?,
    );
    pos = pt_end;
    if pos != buf.len() {
        return Err(FrameError);
    }
    Ok(LeakRevealSocketResponse::Ok {
        report_id,
        generation,
        plaintext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leak_reveal_frame_request_round_trips() {
        let req = LeakRevealSocketRequest {
            capability_hex: LeakRevealToken::new("a".repeat(64)),
        };
        let bytes = encode_request(&req).unwrap();
        assert_eq!(bytes.len(), LEAK_REVEAL_REQUEST_FRAME_LEN);
        assert_eq!(decode_request(&bytes).unwrap(), req);
    }

    #[test]
    fn leak_reveal_frame_request_rejects_bad_shapes() {
        // Wrong version.
        let mut bytes = encode_request(&LeakRevealSocketRequest {
            capability_hex: LeakRevealToken::new("b".repeat(64)),
        })
        .unwrap();
        bytes[0] = 2;
        assert!(decode_request(&bytes).is_err());
        // Trailing byte.
        let mut bytes = encode_request(&LeakRevealSocketRequest {
            capability_hex: LeakRevealToken::new("b".repeat(64)),
        })
        .unwrap();
        bytes.push(0);
        assert!(decode_request(&bytes).is_err());
        // Wrong capability length must not encode.
        assert!(
            encode_request(&LeakRevealSocketRequest {
                capability_hex: LeakRevealToken::new("b".repeat(63)),
            })
            .is_err()
        );
    }

    #[test]
    fn leak_reveal_frame_response_round_trips_and_enforces_bound() {
        let ok = LeakRevealSocketResponse::Ok {
            report_id: "report-1".to_owned(),
            generation: 7,
            plaintext: Zeroizing::new("s3cr3t".to_owned()),
        };
        let bytes = encode_response(&ok);
        match decode_response(&bytes).unwrap() {
            LeakRevealSocketResponse::Ok {
                report_id,
                generation,
                plaintext,
            } => {
                assert_eq!(report_id, "report-1");
                assert_eq!(generation, 7);
                assert_eq!(plaintext.as_str(), "s3cr3t");
            }
            _ => panic!("expected Ok"),
        }

        // Denied round trips by discriminant.
        for d in [
            LeakRevealDenied::Unauthorized,
            LeakRevealDenied::RateLimited,
            LeakRevealDenied::UnavailablePlatform,
            LeakRevealDenied::Internal,
        ] {
            let bytes = encode_response(&LeakRevealSocketResponse::Denied(d));
            match decode_response(&bytes).unwrap() {
                LeakRevealSocketResponse::Denied(got) => assert_eq!(got, d),
                _ => panic!("expected Denied"),
            }
        }

        // Oversize plaintext is refused on encode (re-encoded as Internal).
        let oversize = LeakRevealSocketResponse::Ok {
            report_id: "r".to_owned(),
            generation: 0,
            plaintext: Zeroizing::new("x".repeat(LEAK_REVEAL_MAX_PLAINTEXT_BYTES + 1)),
        };
        let bytes = encode_response(&oversize);
        match decode_response(&bytes).unwrap() {
            LeakRevealSocketResponse::Denied(LeakRevealDenied::Internal) => {}
            _ => panic!("oversize plaintext must encode as Internal"),
        }
    }

    #[test]
    fn leak_reveal_frame_response_rejects_oversize_declared_plaintext() {
        // A hand-built Ok frame declaring a plaintext_len over the cap must be
        // refused on decode (the client never allocates/installs it).
        let mut buf = vec![LEAK_REVEAL_FRAME_VERSION, 0];
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.push(b'r');
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.extend_from_slice(&((LEAK_REVEAL_MAX_PLAINTEXT_BYTES as u32) + 1).to_be_bytes());
        assert!(decode_response(&buf).is_err());
    }
}
