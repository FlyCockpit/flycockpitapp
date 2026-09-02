//! Bounded filesystem reads that never allocate from an untrusted length.
//!
//! Callers supply the cap. This module does not invent resource-exhaustion
//! policy; it only refuses to load more bytes than that cap.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

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
}

/// Length of `path` from metadata, without reading contents.
pub fn file_len(path: &Path) -> io::Result<u64> {
    Ok(std::fs::metadata(path)?.len())
}

/// Read at most `cap` bytes. Errors without allocating `cap` when the file is
/// larger; the metadata length is checked before any content buffer is built.
pub fn read_at_most(path: &Path, cap: u64) -> Result<Vec<u8>, BoundedIoError> {
    let len = file_len(path)?;
    if len > cap {
        return Err(BoundedIoError::Limit {
            what: "file",
            limit: cap,
            actual: len,
        });
    }
    let want = usize::try_from(len).map_err(|_| BoundedIoError::Limit {
        what: "file",
        limit: cap,
        actual: len,
    })?;
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(want)
        .map_err(|_| BoundedIoError::Limit {
            what: "file",
            limit: cap,
            actual: len,
        })?;
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(BoundedIoError::Limit {
            what: "file",
            limit: cap,
            actual: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

/// Compare `path` to `expected` by streaming, so a second full copy is never
/// allocated for the change-detection reread.
pub fn contents_equal(path: &Path, expected: &[u8]) -> io::Result<bool> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len != expected.len() as u64 {
        return Ok(false);
    }
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
    let len = file_len(path)?;
    if len > max_len {
        return Err(BoundedIoError::Limit {
            what: "file",
            limit: max_len,
            actual: len,
        });
    }
    let mut file = File::open(path)?;
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
}
