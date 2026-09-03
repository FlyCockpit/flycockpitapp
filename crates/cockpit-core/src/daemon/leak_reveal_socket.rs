//! Peer-authenticated leak-reveal transport: the production reveal path for a
//! socket-attached TUI. A dedicated owner-only endpoint (path a pure function of
//! the control socket, [`crate::daemon::DaemonPaths::leak_reveal_socket`]) that
//! carries **only** the closed reveal frame ([`crate::daemon::leak_reveal_frame`]),
//! never ordinary proto. On accept it runs the **same** owner peer check the
//! control socket uses ([`crate::daemon::server::validate_peer_owner`]) — no
//! second hand-rolled `SO_PEERCRED`/`getpeereid`/SID path — then hands the
//! presented capability to the channel-agnostic consumption core.
//!
//! On Windows the control identity file names a per-user private pipe; the
//! reveal sibling is `{control_pipe}-leak-reveal` with the same owner ACL.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

use crate::daemon::{DaemonListener, DaemonStream};

use crate::daemon::leak_reveal::{LeakRevealDenied, RevealedLeakSecret, consume_leak_reveal};
use crate::daemon::leak_reveal_frame::{
    LEAK_REVEAL_FRAME_VERSION, LEAK_REVEAL_MAX_REPORT_ID_LEN, LEAK_REVEAL_REQUEST_FRAME_LEN,
    LeakRevealSocketRequest, LeakRevealSocketResponse, decode_response, encode_request,
    encode_response,
};
use crate::daemon::server::{DaemonContext, validate_peer_owner};
use crate::daemon::shutdown::ShutdownPhase;
use crate::leaks::LEAK_REVEAL_MAX_PLAINTEXT_BYTES;

/// Bounded wait for the whole reveal exchange (connect + write + read) so a
/// stalled/misbehaving daemon can never hang the caller. Same-host, same-uid,
/// sub-millisecond in practice; a generous ceiling fails closed.
const LEAK_REVEAL_CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Bounded wait for a client to deliver its complete fixed-length request (and
/// half-close), so a same-uid peer that opens a connection and stalls (or sends
/// a short frame) can't pin a spawned handler forever (resource exhaustion).
const LEAK_REVEAL_SERVER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Serve the dedicated reveal socket until the daemon begins draining. Each
/// accepted connection is peer-checked and handled independently; a peer-uid
/// mismatch or malformed frame closes with no content (no oracle).
pub async fn run_reveal_accept_loop(
    ctx: Arc<DaemonContext>,
    mut listener: DaemonListener,
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
            accepted = accept_reveal(&mut listener) => {
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
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
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
        read_request_frame(&mut stream),
    )
    .await
    {
        Ok(Some(request)) => request,
        // Timeout, malformed, short, or trailing frame: close, no content.
        _ => return,
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    let response = match consume_leak_reveal(&ctx, request.capability_hex.as_str(), now_ms).await {
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
    let mut bytes = encode_response(&response);
    // `response` (and its Zeroizing plaintext) drops here after the encode.
    drop(response);
    let _ = stream.write_all(&bytes).await;
    let _ = stream.flush().await;
    // Shut down the write half so the client observes a clean end-of-response
    // (FIN) instead of blocking, then close. One exchange per connection.
    let _ = stream.shutdown().await;
    // Zeroize the serialized buffer — it held the plaintext bytes.
    bytes.zeroize();
}

/// Read exactly one fixed-length (67-byte) request frame. The request is a
/// closed fixed-size frame, so we read EXACTLY that many bytes — never wait for
/// EOF or an extra byte (the client keeps the connection open to read the
/// response, so waiting for more would deadlock). Returns `None` on a short
/// read, connection error, or malformed frame.
async fn read_request_frame<S>(stream: &mut S) -> Option<LeakRevealSocketRequest>
where
    S: AsyncRead + Unpin,
{
    let mut buf = [0u8; LEAK_REVEAL_REQUEST_FRAME_LEN];
    stream.read_exact(&mut buf).await.ok()?;
    // Reject trailing bytes: a well-behaved client half-closes its write side
    // after the fixed-length request, so the next read is a clean EOF (0 bytes).
    // Any further byte (or a read error) is a protocol violation → fail closed.
    let mut extra = [0u8; 1];
    match stream.read(&mut extra).await {
        Ok(0) => {}
        _ => return None,
    }
    crate::daemon::leak_reveal_frame::decode_request(&buf).ok()
}

/// Connect to a daemon's dedicated reveal socket, present `capability`, and
/// return the revealed secret or a content-free denial. Used by the socket-
/// attached TUI. A malformed capability (not 64 hex chars) fails closed as
/// `Unauthorized` without contacting the daemon; connect failure (stale/missing
/// socket after restart) is `UnavailablePlatform`.
pub(crate) async fn reveal_leak_secret_over_socket(
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
        // Half-close the write side: the request is a fixed-length frame, so
        // this signals a clean end-of-request (EOF) to the server's trailing-
        // byte check. The read half stays open to receive the response.
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
        use tokio::net::windows::named_pipe::ClientOptions;
        let pipe = cockpit_host::named_pipe::read_pipe_identity(reveal_socket)?;
        Ok(ClientOptions::new().open(pipe.as_str())?)
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
pub fn bind_reveal_socket(ctx: &DaemonContext) -> Result<DaemonListener> {
    let path = ctx.paths.leak_reveal_socket();
    let _ = std::fs::remove_file(&path);
    #[cfg(unix)]
    {
        crate::daemon::bind_private_socket(&path)
            .with_context(|| format!("binding leak-reveal socket {}", path.display()))
    }
    #[cfg(windows)]
    {
        let control = cockpit_host::named_pipe::read_pipe_identity(&ctx.paths.socket)
            .context("reading control pipe identity for leak-reveal sibling")?;
        let reveal = control
            .leak_reveal_sibling()
            .context("deriving leak-reveal pipe name")?;
        crate::daemon::windows_pipe::NamedPipeListener::bind_named(&path, reveal, true)
            .with_context(|| format!("binding leak-reveal pipe {}", path.display()))
    }
}
