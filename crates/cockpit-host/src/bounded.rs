//! Bounded filesystem reads that never allocate from an untrusted length.
//!
//! Callers supply the cap. This module does not invent resource-exhaustion
//! policy; it only refuses to load more bytes than that cap.
//!
//! Path reads refuse non-regular files (FIFOs, sockets, devices) before any
//! content is accumulated, and they cap bytes *during* the read so a growing
//! regular file cannot outrun a stale `metadata.len()`.

use std::fs::File;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

const STREAM_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum BoundedIoError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{what} exceeds the {limit} byte limit ({actual} bytes)")]
    Limit {
        what: &'static str,
        limit: u64,
        actual: u64,
    },
    #[error("{what} is not a regular file")]
    NotRegular { what: &'static str },
}

/// Length of `path` from metadata, without reading contents.
pub fn file_len(path: &Path) -> io::Result<u64> {
    Ok(std::fs::metadata(path)?.len())
}

/// Open `path` for a bounded content read: non-regular files are rejected
/// without blocking on a FIFO writer, and the returned handle is blocking.
fn open_regular_file(path: &Path) -> Result<File, BoundedIoError> {
    let file = open_nonblocking_read(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(BoundedIoError::NotRegular { what: "file" });
    }
    clear_nonblock(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn open_nonblocking_read(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_nonblocking_read(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(unix)]
fn clear_nonblock(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn clear_nonblock(_file: &File) -> io::Result<()> {
    Ok(())
}

/// Read at most `cap` bytes. Errors without allocating `cap` when the file is
/// larger; a stale or zero metadata length is never treated as the readable
/// size — bytes are capped while they are read.
pub fn read_at_most(path: &Path, cap: u64) -> Result<Vec<u8>, BoundedIoError> {
    let file = open_regular_file(path)?;
    let len = file.metadata()?.len();
    if len > cap {
        return Err(BoundedIoError::Limit {
            what: "file",
            limit: cap,
            actual: len,
        });
    }
    read_reader_at_most(file, cap, "file")
}

/// Compare `path` to `expected` by streaming, so a second full copy is never
/// allocated for the change-detection reread. Non-regular files fail closed
/// instead of blocking on a FIFO.
pub fn contents_equal(path: &Path, expected: &[u8]) -> Result<bool, BoundedIoError> {
    let mut file = open_regular_file(path)?;
    let mut buf = [0u8; STREAM_BUFFER_BYTES];
    let mut offset = 0usize;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(offset == expected.len());
        }
        let Some(slice) = expected.get(offset..offset + n) else {
            return Ok(false);
        };
        if slice != &buf[..n] {
            return Ok(false);
        }
        offset += n;
    }
}

/// Prefix plus full-file digest, streamed so the daemon never holds more than
/// `prefix_cap` content bytes plus a small read buffer.
pub struct PrefixedFile {
    pub prefix: Vec<u8>,
    pub digest: [u8; 32],
    pub len: u64,
}

pub fn read_prefix_and_hash(
    path: &Path,
    prefix_cap: usize,
    max_len: u64,
) -> Result<PrefixedFile, BoundedIoError> {
    let file = open_regular_file(path)?;
    let len = file.metadata()?.len();
    if len > max_len {
        return Err(BoundedIoError::Limit {
            what: "file",
            limit: max_len,
            actual: len,
        });
    }
    let mut file = file;
    let mut hasher = Sha256::new();
    let mut prefix = Vec::new();
    let mut buf = [0u8; STREAM_BUFFER_BYTES];
    let mut read_total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        read_total = read_total
            .checked_add(n as u64)
            .ok_or_else(|| BoundedIoError::Limit {
                what: "file",
                limit: max_len,
                actual: u64::MAX,
            })?;
        if read_total > max_len {
            return Err(BoundedIoError::Limit {
                what: "file",
                limit: max_len,
                actual: read_total,
            });
        }
        hasher.update(&buf[..n]);
        if prefix.len() < prefix_cap {
            let take = (prefix_cap - prefix.len()).min(n);
            prefix.extend_from_slice(&buf[..take]);
        }
    }
    Ok(PrefixedFile {
        prefix,
        digest: hasher.finalize().into(),
        len: read_total,
    })
}

/// Read one `\n`-terminated line from `reader` into `buf`, failing if the line
/// would exceed `max_bytes`.
///
/// This replaces `AsyncBufReadExt::read_line`, whose accumulator grows without
/// bound: a hostile or broken peer can emit a single newline-free line and OOM
/// the host. Return value matches `read_line`: bytes appended, `0` at EOF.
pub async fn read_line_capped<R>(
    reader: &mut R,
    buf: &mut String,
    max_bytes: usize,
    what: &str,
) -> io::Result<usize>
where
    R: AsyncBufRead + Unpin,
{
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        let available = loop {
            match reader.fill_buf().await {
                Ok(chunk) => break chunk,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        };
        if available.is_empty() {
            break;
        }
        let newline = available.iter().position(|&b| b == b'\n');
        let take = newline.map(|pos| pos + 1).unwrap_or(available.len());
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if bytes.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what} exceeded {max_bytes} bytes; treating peer as hostile"),
            ));
        }
        if newline.is_some() {
            break;
        }
    }
    match std::str::from_utf8(&bytes) {
        Ok(line) => {
            buf.push_str(line);
            Ok(line.len())
        }
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        )),
    }
}

/// Copy from `reader` until EOF or `cap + 1` bytes, whichever comes first.
/// Errors when the stream exceeds `cap` instead of growing without bound.
pub fn read_reader_at_most<R: Read>(
    reader: R,
    cap: u64,
    what: &'static str,
) -> Result<Vec<u8>, BoundedIoError> {
    let take = cap.saturating_add(1);
    let mut limited = reader.take(take);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(BoundedIoError::Limit {
            what,
            limit: cap,
            actual: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn read_at_most_rejects_before_loading_an_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge");
        let file = File::create(&path).unwrap();
        file.set_len(64).unwrap();
        drop(file);
        let err = read_at_most(&path, 32).unwrap_err();
        match err {
            BoundedIoError::Limit {
                limit: 32,
                actual: 64,
                ..
            } => {}
            other => panic!("expected limit error, got {other}"),
        }
    }

    #[test]
    fn read_at_most_loads_a_file_at_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exact");
        std::fs::write(&path, b"abcd").unwrap();
        assert_eq!(read_at_most(&path, 4).unwrap(), b"abcd");
    }

    #[test]
    fn contents_equal_does_not_require_a_second_buffer_of_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eq");
        std::fs::write(&path, b"hello world").unwrap();
        assert!(contents_equal(&path, b"hello world").unwrap());
        assert!(!contents_equal(&path, b"hello World").unwrap());
        assert!(!contents_equal(&path, b"hello").unwrap());
    }

    #[test]
    fn read_prefix_and_hash_caps_the_prefix_and_hashes_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stream");
        let body = vec![7u8; 10_000];
        std::fs::write(&path, &body).unwrap();
        let got = read_prefix_and_hash(&path, 32, 10_000).unwrap();
        assert_eq!(got.prefix.len(), 32);
        assert_eq!(got.prefix, &body[..32]);
        assert_eq!(got.len, 10_000);
        assert_eq!(got.digest, Sha256::digest(&body).as_slice());
    }

    #[test]
    fn read_prefix_and_hash_rejects_metadata_over_max() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("over");
        let file = File::create(&path).unwrap();
        file.set_len(100).unwrap();
        drop(file);
        assert!(matches!(
            read_prefix_and_hash(&path, 8, 50),
            Err(BoundedIoError::Limit {
                limit: 50,
                actual: 100,
                ..
            })
        ));
    }

    #[test]
    fn read_reader_at_most_stops_a_lying_length() {
        let err =
            read_reader_at_most(std::io::Cursor::new(vec![1u8; 50]), 16, "zip entry").unwrap_err();
        match err {
            BoundedIoError::Limit {
                what: "zip entry",
                limit: 16,
                actual: 17,
            } => {}
            other => panic!("expected capped read, got {other}"),
        }
    }

    #[test]
    fn read_reader_at_most_accepts_an_exact_cap() {
        let bytes =
            read_reader_at_most(std::io::Cursor::new(vec![9u8; 8]), 8, "zip entry").unwrap();
        assert_eq!(bytes, vec![9u8; 8]);
    }

    #[test]
    fn write_then_equal_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"payload").unwrap();
        drop(file);
        assert_eq!(read_at_most(&path, 64).unwrap(), b"payload");
    }

    #[cfg(unix)]
    fn mkfifo(path: &std::path::Path) {
        let c_path = std::ffi::CString::new(path.to_str().expect("utf-8 fifo path")).unwrap();
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo {}", path.display());
    }

    #[cfg(unix)]
    #[test]
    fn read_at_most_rejects_a_fifo_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe");
        mkfifo(&path);
        let started = std::time::Instant::now();
        let err = read_at_most(&path, 1024).unwrap_err();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "FIFO open must not block waiting for a writer"
        );
        assert!(
            matches!(err, BoundedIoError::NotRegular { .. }),
            "got {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn contents_equal_rejects_a_fifo_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe");
        mkfifo(&path);
        let started = std::time::Instant::now();
        let err = contents_equal(&path, b"").unwrap_err();
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(
            matches!(err, BoundedIoError::NotRegular { .. }),
            "got {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_prefix_and_hash_rejects_a_fifo_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe");
        mkfifo(&path);
        let started = std::time::Instant::now();
        let err = read_prefix_and_hash(&path, 8, 1024).unwrap_err();
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(
            matches!(err, BoundedIoError::NotRegular { .. }),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn read_line_capped_rejects_a_newline_free_oversize_stream() {
        let oversized = vec![b'x'; 17];
        let mut reader = tokio::io::BufReader::new(std::io::Cursor::new(oversized));
        let mut buf = String::new();
        let err = read_line_capped(&mut reader, &mut buf, 16, "header line")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("header line"), "{err}");
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn read_line_capped_returns_a_terminated_line() {
        let mut reader = tokio::io::BufReader::new(std::io::Cursor::new(b"hello\nrest"));
        let mut buf = String::new();
        let n = read_line_capped(&mut reader, &mut buf, 16, "header line")
            .await
            .unwrap();
        assert_eq!(n, 6);
        assert_eq!(buf, "hello\n");
    }
}
