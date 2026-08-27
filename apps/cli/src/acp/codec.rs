//! ACP-prescribed LF stdio codec.
//!
//! One UTF-8 JSON-RPC 2.0 object per physical LF-delimited line. Not LSP
//! `Content-Length` framing. The inbound/outbound cap is the UTF-8 byte
//! length of the JSON value after stripping the inbound LF or before
//! appending the outbound LF.

use std::io::{self, Write};

use super::AcpTransportCounters;
use super::classify::classify;

/// Exact UTF-8 byte cap for one ACP JSON-RPC frame, LF excluded.
pub const ACP_JSON_FRAME_MAX_BYTES_V1: usize = 2_097_152;

/// Canonical cap for the nested forwarded-MCP `mcpServers` vector.
pub const ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcpFrameError {
    InvalidUtf8,
    OverLimit { json_bytes: usize },
    IncompleteEof { json_bytes: usize },
    EmbeddedLineBreak,
    ContentLengthFraming,
    CarriageReturnFraming,
    NonJsonObject,
    BatchArray,
    Empty,
    Io(String),
}

impl std::fmt::Display for AcpFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUtf8 => f.write_str("ACP frame is not valid UTF-8"),
            Self::OverLimit { json_bytes } => {
                write!(
                    f,
                    "ACP frame exceeds {ACP_JSON_FRAME_MAX_BYTES_V1} bytes ({json_bytes})"
                )
            }
            Self::IncompleteEof { json_bytes } => {
                write!(f, "ACP frame ended at EOF without LF ({json_bytes} bytes)")
            }
            Self::EmbeddedLineBreak => f.write_str("ACP frame contains an embedded physical LF"),
            Self::ContentLengthFraming => f.write_str("ACP frame uses Content-Length/LSP framing"),
            Self::CarriageReturnFraming => {
                f.write_str("ACP frame uses forbidden carriage-return framing")
            }
            Self::NonJsonObject => f.write_str("ACP frame is not a JSON object"),
            Self::BatchArray => f.write_str("ACP v1 does not accept JSON-RPC batch arrays"),
            Self::Empty => f.write_str("ACP frame is empty"),
            Self::Io(message) => write!(f, "ACP stdio I/O error: {message}"),
        }
    }
}

impl std::error::Error for AcpFrameError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcpFrame {
    /// UTF-8 JSON object bytes, LF excluded.
    pub json: String,
}

impl AcpFrame {
    pub fn byte_len(&self) -> usize {
        self.json.len()
    }
}

/// Reads complete LF-delimited frames from a byte source.
pub struct AcpLineReader<R> {
    inner: R,
    pending: Vec<u8>,
    closed: bool,
}

impl<R> AcpLineReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            closed: false,
        }
    }
}

impl<R: io::Read> AcpLineReader<R> {
    /// Read the next complete frame. `Ok(None)` is a clean EOF with no leftover.
    pub fn read_frame(
        &mut self,
        counters: &mut AcpTransportCounters,
    ) -> Result<Option<AcpFrame>, AcpFrameError> {
        if self.closed && self.pending.is_empty() {
            return Ok(None);
        }
        loop {
            if let Some(frame) = self.take_complete_line(counters)? {
                return Ok(Some(frame));
            }
            if self.closed {
                if self.pending.is_empty() {
                    return Ok(None);
                }
                let json_bytes = self.pending.len();
                self.pending.clear();
                counters.frames_rejected += 1;
                return Err(AcpFrameError::IncompleteEof { json_bytes });
            }
            let mut buf = [0u8; 8192];
            match self.inner.read(&mut buf) {
                Ok(0) => {
                    self.closed = true;
                }
                Ok(n) => self.pending.extend_from_slice(&buf[..n]),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(AcpFrameError::Io(err.to_string())),
            }
            if self.pending.len() > ACP_JSON_FRAME_MAX_BYTES_V1 && !self.pending.contains(&b'\n') {
                let json_bytes = self.pending.len();
                self.pending.clear();
                self.closed = true;
                counters.frames_rejected += 1;
                return Err(AcpFrameError::OverLimit { json_bytes });
            }
        }
    }

    fn take_complete_line(
        &mut self,
        counters: &mut AcpTransportCounters,
    ) -> Result<Option<AcpFrame>, AcpFrameError> {
        let Some(newline_at) = self.pending.iter().position(|b| *b == b'\n') else {
            return Ok(None);
        };
        let mut line: Vec<u8> = self.pending.drain(..=newline_at).collect();
        line.pop();
        let json = match String::from_utf8(line) {
            Ok(json) => json,
            Err(_) => {
                counters.frames_rejected += 1;
                return Err(AcpFrameError::InvalidUtf8);
            }
        };
        if looks_like_content_length(&json) {
            counters.frames_rejected += 1;
            return Err(AcpFrameError::ContentLengthFraming);
        }
        if json.contains('\r') {
            counters.frames_rejected += 1;
            return Err(AcpFrameError::CarriageReturnFraming);
        }
        if json.contains('\n') {
            counters.frames_rejected += 1;
            return Err(AcpFrameError::EmbeddedLineBreak);
        }
        if json.len() > ACP_JSON_FRAME_MAX_BYTES_V1 {
            counters.frames_rejected += 1;
            return Err(AcpFrameError::OverLimit {
                json_bytes: json.len(),
            });
        }
        reject_non_acp_object(&json, counters)?;
        Ok(Some(AcpFrame { json }))
    }
}

/// Serialized stdout writer: one JSON value, then exactly one LF.
pub struct AcpLineWriter<W> {
    inner: W,
    bytes_written: usize,
}

impl<W> AcpLineWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            bytes_written: 0,
        }
    }

    pub fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    Complete,
    Partial { written: usize },
    Failed,
}

pub trait FrameSink {
    fn write_json_value(
        &mut self,
        json: &str,
        counters: &mut AcpTransportCounters,
    ) -> Result<WriteOutcome, AcpFrameError>;
}

impl<W: Write> FrameSink for AcpLineWriter<W> {
    fn write_json_value(
        &mut self,
        json: &str,
        counters: &mut AcpTransportCounters,
    ) -> Result<WriteOutcome, AcpFrameError> {
        write_checked_frame(&mut self.inner, json, &mut self.bytes_written, counters)
    }
}

/// In-memory sink used by the permission registry and hermetic transcripts.
#[derive(Debug, Default)]
pub struct MemoryFrameSink {
    pub frames: Vec<String>,
    pub fail_next: bool,
    pub partial_next: Option<usize>,
    pub closed: bool,
}

impl FrameSink for MemoryFrameSink {
    fn write_json_value(
        &mut self,
        json: &str,
        counters: &mut AcpTransportCounters,
    ) -> Result<WriteOutcome, AcpFrameError> {
        if self.closed {
            return Err(AcpFrameError::Io("writer closed".into()));
        }
        if json.len() > ACP_JSON_FRAME_MAX_BYTES_V1 {
            return Err(AcpFrameError::OverLimit {
                json_bytes: json.len(),
            });
        }
        if json.contains('\n') {
            return Err(AcpFrameError::EmbeddedLineBreak);
        }
        if self.fail_next {
            self.fail_next = false;
            self.closed = true;
            return Ok(WriteOutcome::Failed);
        }
        if let Some(written) = self.partial_next.take() {
            self.closed = true;
            return Ok(WriteOutcome::Partial { written });
        }
        self.frames.push(json.to_string());
        let _ = counters;
        Ok(WriteOutcome::Complete)
    }
}

pub fn prepare_outbound_json(json: &str) -> Result<(), AcpFrameError> {
    if json.len() > ACP_JSON_FRAME_MAX_BYTES_V1 {
        return Err(AcpFrameError::OverLimit {
            json_bytes: json.len(),
        });
    }
    if json.contains('\n') {
        return Err(AcpFrameError::EmbeddedLineBreak);
    }
    if json.contains('\r') {
        return Err(AcpFrameError::EmbeddedLineBreak);
    }
    if classify(json).is_err() {
        return Err(AcpFrameError::Io(
            "outbound value is not one valid JSON-RPC 2.0 message".into(),
        ));
    }
    Ok(())
}

fn write_checked_frame<W: Write>(
    writer: &mut W,
    json: &str,
    bytes_written: &mut usize,
    _counters: &mut AcpTransportCounters,
) -> Result<WriteOutcome, AcpFrameError> {
    prepare_outbound_json(json)?;
    match writer.write_all(json.as_bytes()) {
        Ok(()) => {}
        Err(err) => {
            return if *bytes_written > 0 || json.is_empty() {
                Err(AcpFrameError::Io(err.to_string()))
            } else {
                Ok(WriteOutcome::Failed)
            };
        }
    }
    *bytes_written += json.len();
    match writer.write_all(b"\n") {
        Ok(()) => {
            *bytes_written += 1;
            writer
                .flush()
                .map_err(|err| AcpFrameError::Io(err.to_string()))?;
            Ok(WriteOutcome::Complete)
        }
        Err(err) => {
            let _ = err;
            Ok(WriteOutcome::Partial {
                written: json.len(),
            })
        }
    }
}

pub fn reject_non_acp_object(
    json: &str,
    counters: &mut AcpTransportCounters,
) -> Result<(), AcpFrameError> {
    if json.is_empty() {
        counters.frames_rejected += 1;
        return Err(AcpFrameError::Empty);
    }
    if looks_like_content_length(json) {
        counters.frames_rejected += 1;
        return Err(AcpFrameError::ContentLengthFraming);
    }
    let trimmed = json.trim_start_matches([' ', '\t']);
    if trimmed.starts_with('[') {
        counters.frames_rejected += 1;
        return Err(AcpFrameError::BatchArray);
    }
    if !trimmed.starts_with('{') {
        counters.frames_rejected += 1;
        return Err(AcpFrameError::NonJsonObject);
    }
    Ok(())
}

fn looks_like_content_length(json: &str) -> bool {
    let head = json.trim_start_matches([' ', '\t', '\r']);
    let lower = head.to_ascii_lowercase();
    lower.starts_with("content-length:") || lower.starts_with("content-type:")
}

/// Diagnose on stderr only. Never write diagnostics to stdout.
pub fn write_diagnostic(stderr: &mut dyn Write, error: &AcpFrameError) {
    let _ = writeln!(stderr, "acp: {error}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::AcpTransportCounters;
    use std::io::Cursor;

    fn read_one(bytes: &[u8]) -> Result<Option<AcpFrame>, AcpFrameError> {
        let mut reader = AcpLineReader::new(Cursor::new(bytes.to_vec()));
        let mut counters = AcpTransportCounters::default();
        reader.read_frame(&mut counters)
    }

    #[test]
    fn acp_transport_codec_accepts_object_plus_lf() {
        let frame = read_one(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}
"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            frame.json,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#
        );
    }

    #[test]
    fn acp_transport_codec_rejects_content_length() {
        let err = read_one(b"Content-Length: 32\n").unwrap_err();
        assert!(matches!(err, AcpFrameError::ContentLengthFraming));
    }

    #[test]
    fn acp_transport_codec_rejects_batch_array() {
        let err = read_one(b"[]\n").unwrap_err();
        assert!(matches!(err, AcpFrameError::BatchArray));
    }

    #[test]
    fn acp_transport_codec_rejects_incomplete_eof() {
        let err = read_one(br#"{"jsonrpc":"2.0""#).unwrap_err();
        assert!(matches!(err, AcpFrameError::IncompleteEof { .. }));
    }

    #[test]
    fn acp_transport_codec_rejects_invalid_utf8() {
        let err = read_one(&[0xff, 0xfe, b'\n']).unwrap_err();
        assert!(matches!(err, AcpFrameError::InvalidUtf8));
    }

    #[test]
    fn acp_transport_codec_rejects_carriage_return_framing() {
        let err = read_one(b"{\"jsonrpc\":\"2.0\"}\r{\"id\":1}\n").unwrap_err();
        assert!(matches!(err, AcpFrameError::CarriageReturnFraming));
    }

    #[test]
    fn acp_transport_codec_rejects_crlf() {
        let err =
            read_one(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\r\n").unwrap_err();
        assert!(matches!(err, AcpFrameError::CarriageReturnFraming));
    }

    #[test]
    fn acp_transport_codec_exact_max_and_max_plus_one() {
        let max = make_object_of_size(ACP_JSON_FRAME_MAX_BYTES_V1);
        assert_eq!(max.len(), ACP_JSON_FRAME_MAX_BYTES_V1);
        let mut ok = max.as_bytes().to_vec();
        ok.push(b'\n');
        read_one(&ok).unwrap().unwrap();

        let over = make_object_of_size(ACP_JSON_FRAME_MAX_BYTES_V1 + 1);
        let mut bad = over.as_bytes().to_vec();
        bad.push(b'\n');
        let err = read_one(&bad).unwrap_err();
        assert!(matches!(err, AcpFrameError::OverLimit { .. }));
    }

    #[test]
    fn acp_transport_codec_multibyte_hits_both_boundaries() {
        let max = make_multibyte_object_of_size(ACP_JSON_FRAME_MAX_BYTES_V1);
        assert_eq!(max.len(), ACP_JSON_FRAME_MAX_BYTES_V1);
        let mut ok = max.into_bytes();
        ok.push(b'\n');
        read_one(&ok).unwrap().unwrap();

        let over = make_multibyte_object_of_size(ACP_JSON_FRAME_MAX_BYTES_V1 + 1);
        let mut bad = over.into_bytes();
        bad.push(b'\n');
        assert!(matches!(
            read_one(&bad).unwrap_err(),
            AcpFrameError::OverLimit { .. }
        ));
    }

    #[test]
    fn acp_transport_codec_incomplete_at_limit_eof() {
        let max = make_object_of_size(ACP_JSON_FRAME_MAX_BYTES_V1);
        let err = read_one(max.as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            AcpFrameError::IncompleteEof {
                json_bytes: ACP_JSON_FRAME_MAX_BYTES_V1
            }
        ));
    }

    #[test]
    fn acp_transport_codec_writer_appends_one_lf() {
        let mut sink = Vec::new();
        let mut writer = AcpLineWriter::new(&mut sink);
        let mut counters = AcpTransportCounters::default();
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        assert_eq!(
            writer.write_json_value(json, &mut counters).unwrap(),
            WriteOutcome::Complete
        );
        assert_eq!(sink, format!("{json}\n").into_bytes());
    }

    #[test]
    fn acp_transport_codec_writer_accepts_exact_max_before_appending_lf() {
        let json = make_object_of_size(ACP_JSON_FRAME_MAX_BYTES_V1);
        let mut sink = Vec::new();
        let mut writer = AcpLineWriter::new(&mut sink);
        let mut counters = AcpTransportCounters::default();
        assert_eq!(
            writer.write_json_value(&json, &mut counters).unwrap(),
            WriteOutcome::Complete
        );
        assert_eq!(sink.len(), ACP_JSON_FRAME_MAX_BYTES_V1 + 1);
        assert_eq!(&sink[..ACP_JSON_FRAME_MAX_BYTES_V1], json.as_bytes());
        assert_eq!(sink[ACP_JSON_FRAME_MAX_BYTES_V1], b'\n');
    }

    #[test]
    fn acp_transport_codec_outbound_overflow_before_write() {
        let mut sink = Vec::new();
        let mut writer = AcpLineWriter::new(&mut sink);
        let mut counters = AcpTransportCounters::default();
        let json = make_object_of_size(ACP_JSON_FRAME_MAX_BYTES_V1 + 1);
        let err = writer.write_json_value(&json, &mut counters).unwrap_err();
        assert!(matches!(err, AcpFrameError::OverLimit { .. }));
        assert!(sink.is_empty());
    }

    #[test]
    fn acp_transport_codec_rejects_structurally_invalid_outbound_jsonrpc() {
        for invalid in [
            r#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#,
            r#"{"jsonrpc":"1.0","note":"\"jsonrpc\":\"2.0\""}"#,
            r#"{"note":"\"jsonrpc\":\"2.0\""}"#,
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r",
        ] {
            let mut sink = Vec::new();
            let mut writer = AcpLineWriter::new(&mut sink);
            assert!(
                writer
                    .write_json_value(invalid, &mut AcpTransportCounters::default())
                    .is_err()
            );
            assert!(sink.is_empty());
        }
    }

    pub(crate) fn make_object_of_size(size: usize) -> String {
        make_padded_object("x", size)
    }

    pub(crate) fn make_multibyte_object_of_size(size: usize) -> String {
        make_padded_object("é", size)
    }

    fn make_padded_object(unit: &str, size: usize) -> String {
        let prefix = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"pad":""#;
        let suffix = "\"}}";
        let fixed = prefix.len() + suffix.len();
        assert!(size >= fixed + unit.len());
        let mut pad = String::new();
        while fixed + pad.len() + unit.len() <= size {
            pad.push_str(unit);
        }
        while fixed + pad.len() < size {
            pad.push('a');
        }
        let mut out = String::with_capacity(size);
        out.push_str(prefix);
        out.push_str(&pad);
        out.push_str(suffix);
        debug_assert_eq!(out.len(), size);
        out
    }
}
