//! Peer-authenticated leak-reveal transport: the production reveal path for a
//! socket-attached TUI. A dedicated owner-only endpoint (path a pure function of
//! the control socket, [`crate::daemon::DaemonPaths::leak_reveal_socket`]) that
//! carries only bounded one-shot sensitive frames: leak reveal and onboarding
//! passphrase ingress, never ordinary proto. On accept it runs the **same** owner peer check the
//! control socket uses ([`crate::daemon::server::validate_peer_owner`]) — no
//! second hand-rolled `SO_PEERCRED`/`getpeereid`/SID path — then hands the
//! presented capability to the channel-agnostic consumption core.
//!
//! On Windows the control identity file names a per-user private pipe; the
//! reveal sibling is `{control_pipe}-leak-reveal` with the same owner ACL.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::AsyncWrite;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroize;

use crate::daemon::{DaemonListener, DaemonStream};

use crate::daemon::leak_reveal::LeakRevealDenied;
use crate::daemon::leak_reveal::{RevealedLeakSecret, consume_leak_reveal};
use crate::daemon::leak_reveal_frame::{
    LEAK_REVEAL_FRAME_VERSION, LEAK_REVEAL_MAX_REPORT_ID_LEN, decode_response, encode_request,
};
use crate::daemon::leak_reveal_frame::{
    LEAK_REVEAL_REQUEST_FRAME_LEN, LeakRevealSocketRequest, LeakRevealSocketResponse,
    encode_response,
};
use crate::daemon::server::{DaemonContext, socket_peer_identity, validate_peer_owner};
use crate::daemon::shutdown::ShutdownPhase;
use crate::leaks::LEAK_REVEAL_MAX_PLAINTEXT_BYTES;

/// Owns both the bound reveal listener and its discovery path. Dropping this
/// value closes the listener first and retracts the path on every early return,
/// including a later control-publication failure.
pub struct BoundRevealSocket {
    pub(crate) listener: Option<DaemonListener>,
    path: std::path::PathBuf,
}

impl BoundRevealSocket {
    pub(crate) fn new(listener: DaemonListener, path: std::path::PathBuf) -> Self {
        Self {
            listener: Some(listener),
            path,
        }
    }
}

impl Drop for BoundRevealSocket {
    fn drop(&mut self) {
        drop(self.listener.take());
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Bounded wait for the whole reveal exchange (connect + write + read) so a
/// stalled/misbehaving daemon can never hang the caller. Same-host, same-uid,
/// sub-millisecond in practice; a generous ceiling fails closed.
const LEAK_REVEAL_CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Bounded wait for a client to deliver its complete fixed-length request, so a
/// same-uid peer that opens a connection and stalls (or sends a short frame)
/// can't pin a spawned handler forever (resource exhaustion). The request is a
/// closed 67-byte frame; the terminator is that length, not a write-side
/// half-close (named pipes cannot express half-close).
const LEAK_REVEAL_SERVER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Serve the dedicated reveal socket until the daemon begins draining. Each
/// accepted connection is peer-checked and handled independently; a peer-uid
/// mismatch or malformed frame closes with no content (no oracle).
pub async fn run_reveal_accept_loop(
    ctx: Arc<DaemonContext>,
    mut reveal: BoundRevealSocket,
) -> Result<()> {
    let mut shutdown = ctx.shutdown_signal().subscribe();
    if ctx.shutdown_signal().is_draining() {
        return Ok(());
    }
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || ctx.shutdown_signal().is_draining()
                    || matches!(*shutdown.borrow(), ShutdownPhase::Draining | ShutdownPhase::Forced)
                {
                    break;
                }
            }
            accepted = accept_reveal(
                reveal.listener.as_mut().expect("bound reveal listener")
            ) => {
                match accepted {
                    Ok(stream) => {
                        if validate_peer_owner(&stream).is_err() {
                            // Wrong-uid peer: close with no content.
                            continue;
                        }
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            handle_reveal_connection(stream, ctx).await;
                        });
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }
    Ok(())
}

async fn accept_reveal(listener: &mut DaemonListener) -> Result<DaemonStream> {
    #[cfg(unix)]
    {
        listener
            .accept()
            .await
            .map(|(stream, _peer)| stream)
            .context("accepting leak-reveal socket")
    }
    #[cfg(windows)]
    {
        listener.accept().await
    }
}

async fn handle_reveal_connection(mut stream: DaemonStream, ctx: Arc<DaemonContext>) {
    // Bound the request read so a stalled/short-writing peer can't pin this
    // spawned handler forever.
    let request = match tokio::time::timeout(
        LEAK_REVEAL_SERVER_READ_TIMEOUT,
        read_sensitive_request_frame(&mut stream),
    )
    .await
    {
        Ok(Some(request)) => request,
        // Timeout, malformed, short, or trailing frame: close, no content.
        _ => return,
    };
    let mut bytes = match request {
        SensitiveRequestFrame::Leak(request) => {
            let now_ms = chrono::Utc::now().timestamp_millis();
            let response =
                match consume_leak_reveal(&ctx, request.capability_hex.as_str(), now_ms).await {
                    Ok(RevealedLeakSecret {
                        report_id,
                        plaintext,
                        generation,
                    }) => LeakRevealSocketResponse::Ok {
                        report_id,
                        generation,
                        plaintext,
                    },
                    Err(denied) => LeakRevealSocketResponse::Denied(denied),
                };
            let bytes = zeroize::Zeroizing::new(encode_response(&response));
            drop(response);
            bytes
        }
        SensitiveRequestFrame::Onboarding(payload) => {
            let authorized = cockpit_proto::decode_sensitive_onboarding_intent(&payload)
                .ok()
                .and_then(|frame| {
                    let token = frame.owner_capability?;
                    let peer = socket_peer_identity(&stream).ok()?;
                    ctx.peer_credential_registry
                        .verify_sensitive_peer(peer, token.as_str())
                })
                .is_some_and(|(role, _)| role.is_owner_class());
            let response = if authorized {
                crate::daemon::server::handle_ready_onboarding_secure_intent(&ctx, &payload).await
            } else {
                cockpit_proto::SensitiveOnboardingIntentResponse::Rejected(
                    cockpit_proto::SensitiveOnboardingIntentError::Unauthorized,
                )
            };
            cockpit_proto::encode_sensitive_onboarding_response(&response)
                .unwrap_or_else(|_| zeroize::Zeroizing::new(b"COBSR001\x05".to_vec()))
        }
    };
    let _ = stream.write_all(&bytes).await;
    let _ = stream.flush().await;
    // Shut down the write half so the client observes a clean end-of-response
    // (FIN) instead of blocking, then close. One exchange per connection.
    let _ = stream.shutdown().await;
    // Zeroize the serialized buffer — it held the plaintext bytes.
    bytes.zeroize();
}

pub(crate) enum SensitiveRequestFrame {
    Leak(LeakRevealSocketRequest),
    Onboarding(zeroize::Zeroizing<Vec<u8>>),
}

const MAX_ONBOARDING_SENSITIVE_FRAME_BYTES: usize = 128 * 1024;

pub(crate) async fn read_sensitive_request_frame<S>(stream: &mut S) -> Option<SensitiveRequestFrame>
where
    S: AsyncRead + Unpin,
{
    let mut first = [0_u8; 1];
    stream.read_exact(&mut first).await.ok()?;
    if first[0] == LEAK_REVEAL_FRAME_VERSION {
        let mut bytes = [0_u8; LEAK_REVEAL_REQUEST_FRAME_LEN];
        bytes[0] = first[0];
        stream.read_exact(&mut bytes[1..]).await.ok()?;
        if consume_buffered_trailing_byte(stream).await {
            return None;
        }
        return crate::daemon::leak_reveal_frame::decode_request(&bytes)
            .ok()
            .map(SensitiveRequestFrame::Leak);
    }
    if first[0] != b'C' {
        return None;
    }
    let mut encoded = zeroize::Zeroizing::new(Vec::with_capacity(256));
    encoded.push(first[0]);
    let mut magic_tail = [0_u8; 7];
    stream.read_exact(&mut magic_tail).await.ok()?;
    encoded.extend_from_slice(&magic_tail);
    if encoded.as_slice() != b"COBSI001" {
        return None;
    }
    // connection/run/attempt UUIDs + revision + placement
    let mut fixed = [0_u8; 57];
    stream.read_exact(&mut fixed).await.ok()?;
    encoded.extend_from_slice(&fixed);
    read_bounded_len_prefixed(stream, &mut encoded, 2, 512).await?;
    read_bounded_len_prefixed(stream, &mut encoded, 2, 128).await?;
    read_bounded_len_prefixed(stream, &mut encoded, 4, 64 * 1024).await?;
    if encoded.len() > MAX_ONBOARDING_SENSITIVE_FRAME_BYTES
        || cockpit_proto::decode_sensitive_onboarding_intent(&encoded).is_err()
        || consume_buffered_trailing_byte(stream).await
    {
        return None;
    }
    Some(SensitiveRequestFrame::Onboarding(encoded))
}

/// Consume and report one already-buffered byte beyond a closed sensitive
/// frame. Consuming the violating byte lets Unix close with a clean FIN for
/// the common single-byte violation while preserving the no-EOF-wait contract
/// required by duplex named pipes.
async fn consume_buffered_trailing_byte<S>(stream: &mut S) -> bool
where
    S: AsyncRead + Unpin,
{
    let mut extra = [0_u8; 1];
    tokio::select! {
        biased;
        result = stream.read(&mut extra) => !matches!(result, Ok(0)),
        _ = std::future::ready(()) => false,
    }
}

async fn read_bounded_len_prefixed<S>(
    stream: &mut S,
    target: &mut Vec<u8>,
    width: usize,
    max: usize,
) -> Option<()>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length[4 - width..]).await.ok()?;
    target.extend_from_slice(&length[4 - width..]);
    let len = usize::try_from(u32::from_be_bytes(length)).ok()?;
    if len > max || target.len().checked_add(len)? > MAX_ONBOARDING_SENSITIVE_FRAME_BYTES {
        return None;
    }
    let start = target.len();
    target.resize(start + len, 0);
    stream.read_exact(&mut target[start..]).await.ok()?;
    Some(())
}

/// Read exactly one fixed-length (67-byte) request frame. The request is a
/// closed fixed-size frame, so we read EXACTLY that many bytes — never wait for
/// EOF (the client keeps the connection open to read the response, and byte-mode
/// named pipes produce no write-side EOF until the handle fully closes).
/// Trailing bytes already sitting in the buffer are a protocol violation and
/// fail closed; we do not wait for them. Returns `None` on a short read,
/// connection error, extra buffered byte, or malformed frame.
async fn read_request_frame<S>(stream: &mut S) -> Option<LeakRevealSocketRequest>
where
    S: AsyncRead + Unpin,
{
    let mut buf = [0u8; LEAK_REVEAL_REQUEST_FRAME_LEN];
    stream.read_exact(&mut buf).await.ok()?;
    // Reject extra bytes that are already readable. Do not wait for EOF or for
    // a later byte: Unix half-close is not expressible on named pipes, and the
    // client must keep the duplex handle open to read the response.
    if consume_buffered_trailing_byte(stream).await {
        return None;
    }
    crate::daemon::leak_reveal_frame::decode_request(&buf).ok()
}

/// Connect to a daemon's dedicated reveal socket, present `capability`, and
/// return the revealed secret or a content-free denial. Used by the socket-
/// attached TUI. A malformed capability (not 64 hex chars) fails closed as
/// `Unauthorized` without contacting the daemon; connect failure (stale/missing
/// socket after restart) is `UnavailablePlatform`.
pub async fn reveal_leak_secret_over_socket(
    reveal_socket: &Path,
    capability: &crate::daemon::proto::LeakRevealToken,
) -> Result<RevealedLeakSecret, LeakRevealDenied> {
    let request = LeakRevealSocketRequest {
        capability_hex: capability.clone(),
    };
    let bytes = match encode_request(&request) {
        Ok(bytes) => bytes,
        Err(_) => return Err(LeakRevealDenied::Unauthorized),
    };

    // Bound the whole connect+write+read exchange so a stalled daemon can't
    // hang the caller. On timeout, fail closed. The read is length-exact (read
    // the header, then `read_exact` the declared body) — it never waits for EOF.
    let exchange = async {
        let mut stream = connect_reveal(reveal_socket)
            .await
            .map_err(|_| LeakRevealDenied::UnavailablePlatform)?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|_| LeakRevealDenied::UnavailablePlatform)?;
        let _ = stream.flush().await;
        // Best-effort write-side shutdown. Unix delivers EOF to a waiter; byte-
        // mode named pipes treat this as a no-op. The request terminator is the
        // fixed 67-byte frame, so the exchange does not depend on half-close.
        let _ = stream.shutdown().await;
        // `None` here == structural read failure → fail closed as Internal.
        read_response_frame(&mut stream)
            .await
            .ok_or(LeakRevealDenied::Internal)
    };

    let mut frame = match tokio::time::timeout(LEAK_REVEAL_CLIENT_TIMEOUT, exchange).await {
        Ok(Ok(frame)) => frame,
        Ok(Err(denied)) => return Err(denied),
        // Timed out: a misbehaving/stalled daemon. Fail closed.
        Err(_elapsed) => return Err(LeakRevealDenied::Internal),
    };

    let outcome = decode_response(&frame).ok();
    // The assembled frame held the plaintext bytes — scrub before returning.
    frame.zeroize();

    match outcome {
        Some(LeakRevealSocketResponse::Ok {
            report_id,
            generation,
            plaintext,
        }) => Ok(RevealedLeakSecret {
            report_id,
            plaintext,
            generation,
        }),
        Some(LeakRevealSocketResponse::Denied(denied)) => Err(denied),
        // Structural failure / unknown status: fail closed.
        None => Err(LeakRevealDenied::Internal),
    }
}

/// Read exactly one status-tagged response frame off the wire: read the 2-byte
/// header, and for an `Ok` status read each length-prefixed field with
/// `read_exact` (bounded by the closed contract), assembling the complete frame
/// for [`decode_response`]. Returns `None` on any short read, oversize field,
/// or connection error. Never waits for EOF, so the exchange terminates as soon
/// as a full frame is received.
async fn connect_reveal(reveal_socket: &Path) -> Result<impl AsyncRead + AsyncWrite + Unpin> {
    #[cfg(unix)]
    {
        Ok(tokio::net::UnixStream::connect(reveal_socket).await?)
    }
    #[cfg(windows)]
    {
        let pipe = cockpit_host::named_pipe::read_pipe_identity(reveal_socket)?;
        Ok(cockpit_host::named_pipe::connect_client_pipe(&pipe).await?)
    }
}

async fn read_response_frame<S>(stream: &mut S) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.ok()?;
    if header[0] != LEAK_REVEAL_FRAME_VERSION {
        return None;
    }
    let mut frame = header.to_vec();
    // Non-Ok status carries no body.
    if header[1] != 0 {
        return Some(frame);
    }
    // Ok body: report_id_len:u16 | report_id | generation:u64 | plaintext_len:u32 | plaintext.
    let mut u16_buf = [0u8; 2];
    stream.read_exact(&mut u16_buf).await.ok()?;
    let report_id_len = u16::from_be_bytes(u16_buf) as usize;
    if report_id_len > LEAK_REVEAL_MAX_REPORT_ID_LEN {
        return None;
    }
    frame.extend_from_slice(&u16_buf);
    let mut report_id = vec![0u8; report_id_len];
    stream.read_exact(&mut report_id).await.ok()?;
    frame.extend_from_slice(&report_id);

    let mut generation = [0u8; 8];
    stream.read_exact(&mut generation).await.ok()?;
    frame.extend_from_slice(&generation);

    let mut u32_buf = [0u8; 4];
    stream.read_exact(&mut u32_buf).await.ok()?;
    let plaintext_len = u32::from_be_bytes(u32_buf) as usize;
    if plaintext_len > LEAK_REVEAL_MAX_PLAINTEXT_BYTES {
        return None;
    }
    frame.extend_from_slice(&u32_buf);
    let mut plaintext = vec![0u8; plaintext_len];
    let read = stream.read_exact(&mut plaintext).await;
    if read.is_ok() {
        frame.extend_from_slice(&plaintext);
    }
    // Scrub the intermediate plaintext buffer regardless; the assembled `frame`
    // is scrubbed by the caller after decode.
    plaintext.zeroize();
    read.ok()?;
    Some(frame)
}

/// Bind the dedicated 0600 reveal socket at the instance's derived path. Clears
/// any stale socket file first (a previous crash may have left one). Refuses a
/// path that is not owner-only (enforced by [`crate::daemon::bind_private_socket`]).
pub fn bind_reveal_socket(
    paths: &crate::daemon::DaemonPaths,
    #[cfg(windows)] control: &cockpit_host::named_pipe::PipeName,
) -> Result<BoundRevealSocket> {
    let path = paths.leak_reveal_socket();
    let _ = std::fs::remove_file(&path);
    #[cfg(unix)]
    {
        let listener = crate::daemon::bind_private_socket(&path)
            .with_context(|| format!("binding leak-reveal socket {}", path.display()))?;
        Ok(BoundRevealSocket::new(listener, path))
    }
    #[cfg(windows)]
    {
        let reveal = control
            .leak_reveal_sibling()
            .context("deriving leak-reveal pipe name")?;
        let listener =
            crate::daemon::windows_pipe::NamedPipeListener::bind_named(&path, reveal, true)
                .with_context(|| format!("binding leak-reveal pipe {}", path.display()))?;
        Ok(BoundRevealSocket::new(listener, path))
    }
}
