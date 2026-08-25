//! Multipart transcription egress: boundary selection with bounded
//! collision-retry, an injectable first-party egress transport seam, and the
//! dispatch orchestrator.
//!
//! The multipart body is built by [`super::request`]; this module chooses a
//! collision-free boundary and sends the encoded body through the shared
//! first-party egress client. The boundary is `flycockpit-` + 32 lowercase hex
//! from an injected 128-bit value; if the exact `--<boundary>` marker occurs in
//! any field or the audio bytes the boundary is rejected and the next injected
//! value is tried, up to [`super::request::MAX_BOUNDARY_ATTEMPTS`] attempts,
//! after which dispatch fails `transcription_unavailable` with **zero** send.
//!
//! No real network, sleeps, or global environment mutation occurs here. The
//! concrete production transport (binding the vetted egress client, credential
//! headers, and endpoint identity) is owned by the external-runtime layer and
//! implements [`TranscriptionEgressTransport`]; tests inject a fake.
//!
//! TODO(audio-transcription-journal): the external-side-effect journal is the
//! sole handoff authority for the prepared -> dispatching -> terminal
//! (completed / cancelled / completed_after_cancel / failed) state machine and
//! the cancel-vs-prepare-vs-dispatch race matrix (complete-prompt AC6/AC9). It
//! is NOT integrated in this increment. Until it is, no production caller may
//! invoke [`dispatch_multipart`]: the only entry point (the `transcribe_audio`
//! tool) fails closed at the attachment-authority boundary before any
//! reservation, journal record, authorization, or send — so this send path is
//! reachable only from injected-transport unit tests, never live egress. The
//! follow-up must record `prepared` before dispatch, treat the journal terminal
//! as authoritative (a `completed_after_cancel` discards content), and make the
//! whole path exactly-once and fail-closed on any journal error.

use anyhow::{Result, bail};
use async_trait::async_trait;

use super::request::{
    MAX_BOUNDARY_ATTEMPTS, PlannedMultipart, check_boundary_collision, encode_multipart,
    make_boundary,
};

/// A billing-safe, secret-free transport error. Raw provider bodies and
/// credential material never appear here; only a bounded, stable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptionEgressError {
    /// The connection could not be established or was reset.
    Connect,
    /// The request timed out.
    Timeout,
    /// The provider returned a non-success HTTP status. `status` is the code
    /// only; no body is retained.
    Status { status: u16 },
    /// The response exceeded the allowed body limit.
    BodyLimit,
    /// The response could not be interpreted as a transcription response.
    Malformed,
}

impl TranscriptionEgressError {
    /// A stable, redacted reason string safe to surface to the model/history.
    pub fn redacted_reason(&self) -> &'static str {
        match self {
            TranscriptionEgressError::Connect => "transcription_unavailable: connection failed",
            TranscriptionEgressError::Timeout => "transcription_unavailable: request timed out",
            TranscriptionEgressError::Status { .. } => {
                "transcription_failed: provider returned an error status"
            }
            TranscriptionEgressError::BodyLimit => {
                "transcription_unavailable: response exceeded size limit"
            }
            TranscriptionEgressError::Malformed => "invalid_output: response was malformed",
        }
    }
}

/// A successful transcription HTTP response: the status code and the bounded
/// response body bytes. The caller decodes the body with the family-selected
/// decoder in [`super::response`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptionHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The injectable first-party egress transport for transcription. The single
/// production implementation binds the shared vetted egress client, credential
/// headers, and resolved endpoint identity; tests inject a fake with no network.
#[async_trait]
pub trait TranscriptionEgressTransport: Send + Sync {
    /// POST the encoded multipart body with a
    /// `multipart/form-data; boundary=<boundary>` content type. The
    /// implementation supplies the credential header and endpoint; this seam
    /// never carries a secret in its arguments.
    async fn post_multipart(
        &self,
        boundary: &str,
        body: Vec<u8>,
    ) -> std::result::Result<TranscriptionHttpResponse, TranscriptionEgressError>;
}

/// Select a collision-free boundary and produce the encoded multipart body.
///
/// `boundaries` supplies injected 128-bit values (one per attempt). For each,
/// the boundary is formed, the plan is built by `build`, and the exact
/// `--<boundary>` marker is checked against every field value and the audio
/// bytes. The first collision-free plan is encoded and returned with its
/// boundary. After [`MAX_BOUNDARY_ATTEMPTS`] boundaries (or an exhausted
/// iterator) it fails `transcription_unavailable` with no body produced.
pub fn encode_with_boundary_retry(
    audio: &[u8],
    boundaries: &mut dyn Iterator<Item = u128>,
    build: impl Fn(&str) -> Result<PlannedMultipart>,
) -> Result<(String, Vec<u8>)> {
    for _ in 0..MAX_BOUNDARY_ATTEMPTS {
        let Some(value) = boundaries.next() else {
            break;
        };
        let boundary = make_boundary(value);
        let plan = build(&boundary)?;
        if check_boundary_collision(&boundary, &plan.parts, audio).is_ok() {
            let body = encode_multipart(&plan, audio)?;
            return Ok((boundary, body));
        }
        // Collision: try the next injected boundary.
    }
    bail!(
        "transcription_unavailable: no collision-free multipart boundary within {MAX_BOUNDARY_ATTEMPTS} attempts"
    )
}

/// Dispatch a transcription request: select a collision-free boundary, encode
/// the multipart body, and send it through the injected first-party egress
/// transport. On a non-2xx status or transport error, returns a redacted,
/// secret-free error; on success returns the bounded response for decoding.
pub async fn dispatch_multipart(
    audio: &[u8],
    boundaries: &mut dyn Iterator<Item = u128>,
    build: impl Fn(&str) -> Result<PlannedMultipart>,
    transport: &dyn TranscriptionEgressTransport,
) -> Result<TranscriptionHttpResponse> {
    let (boundary, body) = encode_with_boundary_retry(audio, boundaries, build)?;
    match transport.post_multipart(&boundary, body).await {
        Ok(response) if (200..300).contains(&response.status) => Ok(response),
        Ok(response) => bail!(
            "{}",
            TranscriptionEgressError::Status {
                status: response.status
            }
            .redacted_reason()
        ),
        Err(error) => bail!("{}", error.redacted_reason()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::request::{BOUNDARY_PREFIX, MultipartPart, plan_gpt_transcribe};
    use super::*;
    use std::sync::Mutex;

    struct FakeTransport {
        response: TranscriptionHttpResponse,
        seen_boundary: Mutex<Option<String>>,
    }

    #[async_trait]
    impl TranscriptionEgressTransport for FakeTransport {
        async fn post_multipart(
            &self,
            boundary: &str,
            _body: Vec<u8>,
        ) -> std::result::Result<TranscriptionHttpResponse, TranscriptionEgressError> {
            *self.seen_boundary.lock().unwrap() = Some(boundary.to_string());
            Ok(self.response.clone())
        }
    }

    fn build_plan(file_bytes: u64) -> impl Fn(&str) -> Result<PlannedMultipart> {
        move |boundary: &str| plan_gpt_transcribe(file_bytes, None, &[], &[], boundary)
    }

    #[test]
    fn boundary_is_prefix_plus_32_lowercase_hex() {
        let b = make_boundary(0x0123_4567_89ab_cdef_0011_2233_4455_6677u128);
        assert!(b.starts_with(BOUNDARY_PREFIX));
        let rest = b.strip_prefix(BOUNDARY_PREFIX).unwrap();
        assert_eq!(rest.len(), 32);
        assert!(
            rest.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn retry_skips_colliding_boundary() {
        // The audio contains the marker for the FIRST boundary only, forcing a
        // retry onto the second injected value.
        let first = make_boundary(1);
        let audio = format!("padding--{first}padding").into_bytes();
        let mut boundaries = [1u128, 2u128].into_iter();
        let (chosen, body) =
            encode_with_boundary_retry(&audio, &mut boundaries, build_plan(audio.len() as u64))
                .unwrap();
        assert_eq!(chosen, make_boundary(2));
        assert!(!body.is_empty());
    }

    #[test]
    fn retry_exhausts_after_max_attempts() {
        // Every candidate collides, so dispatch fails with zero send.
        let audio_marker = make_boundary(7);
        let audio = format!("x--{audio_marker}x").into_bytes();
        // Supply the same colliding value repeatedly, more than the cap.
        let mut boundaries = std::iter::repeat(7u128).take(MAX_BOUNDARY_ATTEMPTS + 4);
        let err =
            encode_with_boundary_retry(&audio, &mut boundaries, build_plan(audio.len() as u64))
                .unwrap_err();
        assert!(err.to_string().contains("transcription_unavailable"));
    }

    #[tokio::test]
    async fn dispatch_sends_collision_free_boundary_and_returns_body() {
        let audio = b"hello world audio bytes".to_vec();
        let transport = FakeTransport {
            response: TranscriptionHttpResponse {
                status: 200,
                body: br#"{"text":"hi","languages":[]}"#.to_vec(),
            },
            seen_boundary: Mutex::new(None),
        };
        let mut boundaries = [42u128].into_iter();
        let response = dispatch_multipart(
            &audio,
            &mut boundaries,
            build_plan(audio.len() as u64),
            &transport,
        )
        .await
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            transport.seen_boundary.lock().unwrap().as_deref(),
            Some(make_boundary(42).as_str())
        );
    }

    #[tokio::test]
    async fn dispatch_redacts_non_success_status() {
        let audio = b"audio".to_vec();
        let transport = FakeTransport {
            response: TranscriptionHttpResponse {
                status: 500,
                body: b"secret provider error body".to_vec(),
            },
            seen_boundary: Mutex::new(None),
        };
        let mut boundaries = [1u128].into_iter();
        let err = dispatch_multipart(
            &audio,
            &mut boundaries,
            build_plan(audio.len() as u64),
            &transport,
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("transcription_failed"));
        assert!(!msg.contains("secret provider error body"));
    }

    // Silence unused-import warnings if the module grows.
    #[allow(dead_code)]
    fn _use_part(_: MultipartPart) {}
}
