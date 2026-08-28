//! Bounded audio/video inspection and extraction contracts.
//!
//! The first call admits a nested `source` object (`attachment_id`, `path`,
//! or `url`); later calls reuse `source: {attachment_id}`. Paths and URLs
//! are admitted only by the session attachment authority; this module never
//! opens an arbitrary model-supplied path itself.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::capabilities::{BinaryRequirement, CapabilityRemedy};
use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};
use crate::tool_media_authority::{AdmissionDenial, NestedMediaSource, SessionMediaAuthority};

mod runner;
pub use runner::{
    AvArgvRunner, AvRunnerOutput, DEFAULT_FFPROBE_JSON, DEFAULT_MP4_BYTES, DEFAULT_PNG_BYTES,
    DEFAULT_WAV_BYTES, FakeAvArgvRunner, RecordedAvRun, SystemAvArgvRunner,
};

pub const MAX_STORYBOARD_FRAMES: u32 = 64;
pub const DURATION_TOLERANCE_MS: u64 = 1;
pub const MAX_PROCESS_STDOUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PROCESS_STDERR_BYTES: usize = 64 * 1024;
pub const MAX_EXTRACTION_DURATION_MS: u64 = 10 * 60 * 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Milliseconds(pub u64);

impl Milliseconds {
    /// Parse nonnegative decimal seconds without floating-point rounding.
    pub fn from_decimal_seconds(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty() || value.starts_with('-') || value.starts_with('+') {
            bail!("invalid_timestamp: expected nonnegative decimal seconds");
        }
        let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
        if whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
            || fraction.len() > 3
        {
            bail!("invalid_timestamp: precision is limited to integer milliseconds");
        }
        let seconds = whole.parse::<u64>()?;
        let fraction = format!("{fraction:0<3}").parse::<u64>()?;
        Ok(Self(
            seconds
                .checked_mul(1_000)
                .and_then(|ms| ms.checked_add(fraction))
                .ok_or_else(|| anyhow::anyhow!("timestamp_overflow"))?,
        ))
    }

    /// Parse ffprobe's normalized decimal-second fields. FFprobe commonly
    /// emits six fractional digits, while model arguments intentionally stay
    /// limited to exact milliseconds. Accept at most nanosecond precision and
    /// round half-up to the nearest millisecond without floating point.
    fn from_ffprobe_decimal_seconds(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty()
            || value.len() > 32
            || value
                .as_bytes()
                .first()
                .is_some_and(|byte| matches!(*byte, b'-' | b'+'))
        {
            bail!("invalid_media");
        }
        let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
        if whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
            || fraction.len() > 9
        {
            bail!("invalid_media");
        }
        let seconds = whole
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("invalid_media"))?;
        let mut milliseconds = seconds
            .checked_mul(1_000)
            .ok_or_else(|| anyhow::anyhow!("invalid_media"))?;
        let mut digits = [b'0'; 4];
        for (index, byte) in fraction.bytes().take(4).enumerate() {
            digits[index] = byte;
        }
        let integral_fraction = u64::from(digits[0] - b'0') * 100
            + u64::from(digits[1] - b'0') * 10
            + u64::from(digits[2] - b'0');
        milliseconds = milliseconds
            .checked_add(integral_fraction)
            .ok_or_else(|| anyhow::anyhow!("invalid_media"))?;
        if digits[3] >= b'5' {
            milliseconds = milliseconds
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("invalid_media"))?;
        }
        Ok(Self(milliseconds))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interval {
    pub start: Milliseconds,
    pub end: Milliseconds,
}

impl Interval {
    pub fn checked(start: Milliseconds, end: Milliseconds) -> Result<Self> {
        if end <= start {
            bail!("empty_interval: end must be greater than start");
        }
        Ok(Self { start, end })
    }

    pub fn validate_duration(&self, duration: Milliseconds) -> Result<()> {
        if self.end.0 > duration.0.saturating_add(DURATION_TOLERANCE_MS) {
            bail!("interval_out_of_bounds");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCandidate {
    pub index: u32,
    pub disposition_default: bool,
    pub allowed: bool,
}

/// Apply the attachment stream rule: explicit allowed index, otherwise the
/// lowest default stream, otherwise the lowest allowed stream.
pub fn select_stream(streams: &[StreamCandidate], explicit: Option<u32>) -> Result<u32> {
    if let Some(index) = explicit {
        return streams
            .iter()
            .find(|stream| stream.index == index && stream.allowed)
            .map(|stream| stream.index)
            .ok_or_else(|| invalid_input("stream_not_allowed"));
    }
    streams
        .iter()
        .filter(|stream| stream.allowed)
        .min_by_key(|stream| (!stream.disposition_default, stream.index))
        .map(|stream| stream.index)
        .ok_or_else(|| invalid_input("no_allowed_stream"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoryboardMode {
    Every(Milliseconds),
    MaxFrames(u32),
}

pub fn storyboard_timestamps(
    interval: &Interval,
    mode: StoryboardMode,
) -> Result<Vec<Milliseconds>> {
    if interval.start.0 >= interval.end.0 {
        bail!("invalid_interval");
    }
    match mode {
        StoryboardMode::Every(period) => {
            if period.0 == 0 {
                bail!("invalid_sampling_period");
            }
            let mut output = Vec::new();
            let mut timestamp = interval.start.0;
            while timestamp < interval.end.0 {
                if output.len() >= MAX_STORYBOARD_FRAMES as usize {
                    bail!("too_many_frames");
                }
                output.push(Milliseconds(timestamp));
                timestamp = timestamp
                    .checked_add(period.0)
                    .ok_or_else(|| anyhow::anyhow!("timestamp_overflow"))?;
            }
            Ok(output)
        }
        StoryboardMode::MaxFrames(count) => {
            if count == 0 || count > MAX_STORYBOARD_FRAMES {
                bail!("invalid_frame_count");
            }
            if count == 1 {
                return Ok(vec![interval.start]);
            }
            let span = interval.end.0 - interval.start.0 - 1;
            (0..count)
                .map(|k| {
                    let offset = u64::from(k)
                        .checked_mul(span)
                        .ok_or_else(|| anyhow::anyhow!("timestamp_overflow"))?
                        / u64::from(count - 1);
                    Ok(Milliseconds(interval.start.0 + offset))
                })
                .collect()
        }
    }
}

pub fn frame_tolerance_ms(nominal_frame_duration_ms: Option<u64>) -> u64 {
    nominal_frame_duration_ms
        .map(|duration| duration.div_ceil(2).clamp(100, 500))
        .unwrap_or(100)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoryboardFrame {
    pub requested_ms: u64,
    pub actual_pts_ms: u64,
}

/// Source pixel geometry reported with each selected storyboard frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoryboardSourceGeometry {
    pub rotation_degrees: i32,
    pub sar_num: u32,
    pub sar_den: u32,
    pub dar_num: u32,
    pub dar_den: u32,
}

/// Selected frame plus the source rotation/SAR/DAR applied to its pixels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoryboardFrameReport {
    pub requested_ms: u64,
    pub actual_pts_ms: u64,
    pub rotation_degrees: i32,
    pub sar_num: u32,
    pub sar_den: u32,
    pub dar_num: u32,
    pub dar_den: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoryboardSelection {
    pub frames: Vec<StoryboardFrame>,
    pub sample_unavailable_ms: Vec<u64>,
    pub omitted_duplicates: Vec<StoryboardFrame>,
}

/// Copy source rotation/SAR/DAR onto selected frames without changing PTS.
pub fn report_storyboard_frames(
    frames: &[StoryboardFrame],
    source: &StoryboardSourceGeometry,
) -> Vec<StoryboardFrameReport> {
    frames
        .iter()
        .map(|frame| StoryboardFrameReport {
            requested_ms: frame.requested_ms,
            actual_pts_ms: frame.actual_pts_ms,
            rotation_degrees: source.rotation_degrees,
            sar_num: source.sar_num,
            sar_den: source.sar_den,
            dar_num: source.dar_num,
            dar_den: source.dar_den,
        })
        .collect()
}

/// Select the first PTS at or after each request, enforce the positive-delta
/// tolerance, and deduplicate actual PTS while retaining the earliest request.
pub fn select_storyboard_frames(
    requested: &[Milliseconds],
    actual_pts: &[Milliseconds],
    nominal_frame_duration_ms: Option<u64>,
) -> StoryboardSelection {
    let tolerance = frame_tolerance_ms(nominal_frame_duration_ms);
    let mut frames = Vec::new();
    let mut unavailable = Vec::new();
    let mut duplicates = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for request in requested {
        let candidate = actual_pts.iter().copied().find(|pts| pts >= request);
        let Some(actual) = candidate.filter(|pts| pts.0 - request.0 <= tolerance) else {
            unavailable.push(request.0);
            continue;
        };
        let frame = StoryboardFrame {
            requested_ms: request.0,
            actual_pts_ms: actual.0,
        };
        if seen.insert(actual.0) {
            frames.push(frame);
        } else {
            duplicates.push(frame);
        }
    }
    StoryboardSelection {
        frames,
        sample_unavailable_ms: unavailable,
        omitted_duplicates: duplicates,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpec {
    pub program: PathBuf,
    pub argv: Vec<String>,
    pub environment: Vec<(&'static str, String)>,
    pub stdin_closed: bool,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
    pub deadline: Duration,
    pub temp_paths: Vec<PathBuf>,
}

/// Format integer milliseconds as ffmpeg seconds with millisecond precision
/// (`1.500`) without floating-point rounding.
pub fn format_ffmpeg_seconds(ms: u64) -> String {
    format!("{}.{:03}", ms / 1_000, ms % 1_000)
}

fn gcd_u32(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a.max(1)
}

fn process_spec(program: impl Into<PathBuf>, argv: Vec<String>, deadline: Duration) -> ProcessSpec {
    ProcessSpec {
        program: program.into(),
        argv,
        environment: vec![("LC_ALL", "C".into()), ("LANG", "C".into())],
        stdin_closed: true,
        stdout_limit: MAX_PROCESS_STDOUT_BYTES,
        stderr_limit: MAX_PROCESS_STDERR_BYTES,
        deadline,
        temp_paths: Vec::new(),
    }
}

pub fn probe_process(path: &str) -> ProcessSpec {
    process_spec(
        "ffprobe",
        vec![
            "-v".into(),
            "error".into(),
            "-show_format".into(),
            "-show_streams".into(),
            "-show_frames".into(),
            "-of".into(),
            "json".into(),
            path.into(),
        ],
        Duration::from_secs(30),
    )
}

fn storyboard_frame_process(path: &str, stream: u32, timestamp: Milliseconds) -> ProcessSpec {
    process_spec(
        "ffmpeg",
        vec![
            "-v".into(),
            "error".into(),
            "-ss".into(),
            format_ffmpeg_seconds(timestamp.0),
            "-i".into(),
            path.into(),
            "-map".into(),
            format!("0:{stream}"),
            "-frames:v".into(),
            "1".into(),
            "-vf".into(),
            "format=rgb24".into(),
            "-f".into(),
            "image2pipe".into(),
            "-vcodec".into(),
            "png".into(),
            "pipe:1".into(),
        ],
        Duration::from_secs(30),
    )
}

pub fn clip_process(
    input: &str,
    interval: &Interval,
    stream: u32,
    source_audio: Option<(u32, u32, u8)>,
    fps_num: u32,
    fps_den: u32,
) -> ProcessSpec {
    let fps_den = fps_den.max(1);
    let (fps_num, fps_den) = {
        let divisor = gcd_u32(fps_num.max(1), fps_den);
        (fps_num.max(1) / divisor, fps_den / divisor)
    };
    let mut argv = vec![
        "-nostdin".into(),
        "-v".into(),
        "error".into(),
        "-i".into(),
        input.into(),
        "-ss".into(),
        format_ffmpeg_seconds(interval.start.0),
        "-t".into(),
        format_ffmpeg_seconds(interval.end.0.saturating_sub(interval.start.0)),
        "-map".into(),
        format!("0:{stream}"),
        "-vf".into(),
        format!(
            "scale='min(1280,iw)':'min(720,ih)':force_original_aspect_ratio=decrease,fps={fps_num}/{fps_den},format=yuv420p"
        ),
        "-c:v".into(),
        "libx264".into(),
    ];
    if let Some((audio_stream, sample_rate, channels)) = source_audio {
        argv.extend([
            "-map".into(),
            format!("0:{audio_stream}?"),
            "-c:a".into(),
            "aac".into(),
            "-ar".into(),
            sample_rate.min(48_000).to_string(),
            "-ac".into(),
            channels.clamp(1, 2).to_string(),
        ]);
    } else {
        argv.push("-an".into());
    }
    argv.extend([
        "-movflags".into(),
        "+frag_keyframe+empty_moov".into(),
        "-f".into(),
        "mp4".into(),
        "pipe:1".into(),
    ]);
    process_spec("ffmpeg", argv, Duration::from_secs(120))
}

pub fn audio_process(
    input: &str,
    interval: &Interval,
    stream: u32,
    sample_rate: u32,
    channels: u8,
) -> ProcessSpec {
    let rate = sample_rate.min(48_000);
    let channels = channels.clamp(1, 2);
    process_spec(
        "ffmpeg",
        vec![
            "-nostdin".into(),
            "-v".into(),
            "error".into(),
            "-i".into(),
            input.into(),
            "-ss".into(),
            format_ffmpeg_seconds(interval.start.0),
            "-t".into(),
            format_ffmpeg_seconds(interval.end.0.saturating_sub(interval.start.0)),
            "-map".into(),
            format!("0:{stream}"),
            "-vn".into(),
            "-c:a".into(),
            "pcm_s16le".into(),
            "-ar".into(),
            rate.to_string(),
            "-ac".into(),
            channels.to_string(),
            "-f".into(),
            "wav".into(),
            "pipe:1".into(),
        ],
        Duration::from_secs(120),
    )
}

fn source_schema() -> Value {
    json!({
        "anyOf": [
            {
                "type": "object",
                "properties": { "attachment_id": { "type": "string", "minLength": 1 } },
                "required": ["attachment_id"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": { "path": { "type": "string", "minLength": 1 } },
                "required": ["path"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": { "url": { "type": "string", "pattern": "^https://" } },
                "required": ["url"],
                "additionalProperties": false
            }
        ]
    })
}

fn schema(kind: ToolKind) -> Value {
    let mut properties = serde_json::Map::new();
    properties.insert("source".into(), source_schema());
    properties.insert("stream_index".into(), json!({"type":"integer","minimum":0}));
    properties.insert(
        "start".into(),
        json!({"type":"number","minimum":0,"multipleOf":0.001}),
    );
    properties.insert(
        "end".into(),
        json!({"type":"number","exclusiveMinimum":0,"multipleOf":0.001}),
    );
    if kind == ToolKind::InspectVideo {
        properties.insert(
            "sampling".into(),
            json!({
                "anyOf": [
                    {
                        "type": "object",
                        "required": ["every_seconds"],
                        "properties": {
                            "every_seconds": {
                                "type": "number",
                                "exclusiveMinimum": 0,
                                "multipleOf": 0.001
                            }
                        },
                        "additionalProperties": false
                    },
                    {
                        "type": "object",
                        "required": ["max_frames"],
                        "properties": {
                            "max_frames": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": MAX_STORYBOARD_FRAMES
                            }
                        },
                        "additionalProperties": false
                    }
                ]
            }),
        );
    }
    json!({
        "type": "object",
        "properties": properties,
        "required": ["source"],
        "additionalProperties": false
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolKind {
    InspectAudio,
    InspectVideo,
    ExtractVideoClip,
    ExtractAudio,
}

fn requirements(kind: ToolKind) -> Vec<BinaryRequirement> {
    let ffprobe_remedy = if kind == ToolKind::InspectAudio {
        CapabilityRemedy::prose("Install a compatible system FFprobe executable.")
    } else {
        CapabilityRemedy::prose("Install a compatible system FFmpeg/FFprobe pair.")
    };
    let mut result = vec![BinaryRequirement::required("ffprobe", ffprobe_remedy)];
    if kind != ToolKind::InspectAudio {
        result.push(BinaryRequirement::required(
            "ffmpeg",
            CapabilityRemedy::prose("Install a compatible system FFmpeg/FFprobe pair."),
        ));
    }
    result
}

fn validate_tool_args(args: &Value, kind: ToolKind) -> Result<()> {
    let compiled = schema(kind);
    let validator =
        jsonschema::validator_for(&compiled).map_err(|error| invalid_input(error.to_string()))?;
    validator
        .validate(args)
        .map_err(|error| invalid_input(error.to_string()))
}

pub fn parse_nested_source(args: &Value) -> Result<NestedMediaSource> {
    let source = args
        .get("source")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_input("source must be a nested object"))?;
    let attachment_id = source
        .get("attachment_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let path = source
        .get("path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let url = source
        .get("url")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("https://"));
    match (attachment_id, path, url, source.len()) {
        (Some(id), None, None, 1) => Ok(NestedMediaSource::AttachmentId(id.to_string())),
        (None, Some(path), None, 1) => Ok(NestedMediaSource::Path(path.to_string())),
        (None, None, Some(url), 1) => Ok(NestedMediaSource::Url(url.to_string())),
        _ => Err(invalid_input(
            "source must be exactly one of {attachment_id}, {path}, or {url}",
        )),
    }
}

fn ms_from_number(value: &Value) -> Result<Milliseconds> {
    let number = value
        .as_number()
        .ok_or_else(|| invalid_input("timestamp must be a number"))?;
    // Preserve the JSON decimal spelling. Converting through `f64` and
    // formatting to three places can silently round a value to a different
    // interval even when ffmpeg itself accepts exact millisecond decimals.
    Milliseconds::from_decimal_seconds(&number.to_string())
        .map_err(|error| invalid_input(error.to_string()))
}

fn parse_optional_interval(args: &Value) -> Result<Option<Interval>> {
    match (args.get("start"), args.get("end")) {
        (None, None) => Ok(None),
        (Some(start), Some(end)) => Ok(Some(Interval::checked(
            ms_from_number(start)?,
            ms_from_number(end)?,
        )?)),
        _ => Err(invalid_input("start and end must be supplied together")),
    }
}

fn parse_sampling(args: &Value) -> Result<Option<StoryboardMode>> {
    let Some(sampling) = args.get("sampling") else {
        return Ok(None);
    };
    let object = sampling
        .as_object()
        .ok_or_else(|| invalid_input("sampling must be an object"))?;
    if let Some(every) = object.get("every_seconds") {
        let period = ms_from_number(every)?;
        return Ok(Some(StoryboardMode::Every(period)));
    }
    if let Some(max_frames) = object.get("max_frames").and_then(Value::as_u64) {
        return Ok(Some(StoryboardMode::MaxFrames(
            u32::try_from(max_frames).map_err(|_| invalid_input("invalid_frame_count"))?,
        )));
    }
    Err(invalid_input(
        "sampling must set every_seconds or max_frames",
    ))
}

struct ParsedAvArgs {
    source: NestedMediaSource,
    interval: Option<Interval>,
    sampling: Option<StoryboardMode>,
    stream_index: Option<u32>,
}

fn parse_semantic_args(args: &Value, kind: ToolKind) -> Result<ParsedAvArgs> {
    validate_tool_args(args, kind)?;
    let stream_index = args
        .get("stream_index")
        .and_then(Value::as_u64)
        .map(u32::try_from)
        .transpose()
        .map_err(|_| invalid_input("stream_index is out of range"))?;
    let interval = parse_optional_interval(args)?;
    if matches!(kind, ToolKind::ExtractAudio | ToolKind::ExtractVideoClip)
        && interval.as_ref().is_some_and(|interval| {
            interval.end.0.saturating_sub(interval.start.0) > MAX_EXTRACTION_DURATION_MS
        })
    {
        bail!("resource_limit");
    }
    Ok(ParsedAvArgs {
        source: parse_nested_source(args)?,
        interval,
        sampling: if kind == ToolKind::InspectVideo {
            parse_sampling(args)?
        } else {
            None
        },
        stream_index,
    })
}

fn admission_error(denial: AdmissionDenial) -> anyhow::Error {
    match denial {
        AdmissionDenial::NoAuthority => anyhow::anyhow!(
            "media_attachment_authority_unavailable: no session media authority for this context"
        ),
        _ => invalid_input(format!("source_denied:{denial}")),
    }
}

#[derive(Debug, Deserialize)]
struct ProbeDisposition {
    #[serde(default)]
    default: i32,
}

#[derive(Debug, Deserialize)]
struct ProbeStream {
    index: u32,
    codec_type: String,
    #[serde(default)]
    codec_name: String,
    #[serde(default)]
    sample_rate: Option<String>,
    #[serde(default)]
    channels: Option<u32>,
    #[serde(default)]
    width: Option<u32>,
    #[serde(default)]
    height: Option<u32>,
    #[serde(default)]
    time_base: Option<String>,
    #[serde(default)]
    disposition: Option<ProbeDisposition>,
}

#[derive(Debug, Deserialize)]
struct ProbeFrame {
    #[serde(default)]
    media_type: String,
    #[serde(default)]
    stream_index: u32,
    #[serde(default)]
    pts_time: Option<String>,
    #[serde(default)]
    best_effort_timestamp: Option<ProbeInteger>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ProbeInteger {
    Number(i64),
    String(String),
}

impl ProbeInteger {
    fn parse(&self) -> Result<i64> {
        match self {
            Self::Number(value) => Ok(*value),
            Self::String(value) => value
                .parse::<i64>()
                .map_err(|_| anyhow::anyhow!("invalid_media")),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ProbeFormat {
    #[serde(default)]
    duration: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProbeDocument {
    #[serde(default)]
    streams: Vec<ProbeStream>,
    #[serde(default)]
    frames: Vec<ProbeFrame>,
    #[serde(default)]
    format: Option<ProbeFormat>,
}

fn parse_probe_document(bytes: &[u8]) -> Result<ProbeDocument> {
    if bytes.len() > MAX_PROCESS_STDOUT_BYTES {
        bail!("resource_limit");
    }
    let document: ProbeDocument =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid_media"))?;
    if document.streams.is_empty() || document.streams.len() > 64 || document.frames.len() > 250_000
    {
        bail!("invalid_media");
    }
    Ok(document)
}

fn stream_candidates(document: &ProbeDocument, want: &str) -> Vec<StreamCandidate> {
    document
        .streams
        .iter()
        .filter(|stream| stream.codec_type == want)
        .map(|stream| StreamCandidate {
            index: stream.index,
            disposition_default: stream
                .disposition
                .as_ref()
                .is_some_and(|value| value.default != 0),
            allowed: true,
        })
        .collect()
}

fn duration_ms(document: &ProbeDocument) -> Result<Milliseconds> {
    let raw = document
        .format
        .as_ref()
        .and_then(|format| format.duration.as_deref())
        .ok_or_else(|| anyhow::anyhow!("invalid_media"))?;
    let duration = Milliseconds::from_ffprobe_decimal_seconds(raw)?;
    if duration.0 == 0 {
        bail!("invalid_media");
    }
    Ok(duration)
}

fn selected_pts_ms(document: &ProbeDocument, stream: u32) -> Result<Vec<Milliseconds>> {
    let mut pts = Vec::new();
    for frame in &document.frames {
        if frame.media_type != "video" || frame.stream_index != stream {
            continue;
        }
        if let Some(time) = frame.pts_time.as_deref() {
            pts.push(Milliseconds::from_ffprobe_decimal_seconds(time)?);
            continue;
        }
        // `best_effort_timestamp` is expressed in the stream time base, not
        // milliseconds. ffprobe's normalized `pts_time` is the only value we
        // can consume here without silently selecting the wrong frames.
    }
    if pts.windows(2).any(|window| window[1] < window[0]) {
        bail!("invalid_media");
    }
    Ok(pts)
}

fn source_audio_caps(
    document: &ProbeDocument,
    explicit: Option<u32>,
) -> Result<Option<(u32, u32, u8)>> {
    let candidates = stream_candidates(document, "audio");
    if candidates.is_empty() {
        return Ok(None);
    }
    let selected = select_stream(&candidates, explicit)?;
    let found = document
        .streams
        .iter()
        .find(|candidate| candidate.index == selected && candidate.codec_type == "audio")
        .ok_or_else(|| anyhow::anyhow!("invalid_media"))?;
    let rate = found
        .sample_rate
        .as_deref()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| anyhow::anyhow!("invalid_media"))?
        .min(48_000);
    let channels = found
        .channels
        .filter(|value| *value > 0)
        .ok_or_else(|| anyhow::anyhow!("invalid_media"))?
        .min(2) as u8;
    Ok(Some((selected, rate, channels)))
}

fn parse_positive_rational(value: &str) -> Result<(u64, u64)> {
    let (num, den) = value
        .trim()
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid_media"))?;
    let num = num
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid_media"))?;
    let den = den
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid_media"))?;
    if num == 0 || den == 0 {
        bail!("invalid_media");
    }
    Ok((num, den))
}

/// Derive the exact reduced source FPS from integer ffprobe timestamps and the
/// selected stream's exact time base. Decimal `pts_time` is deliberately not
/// used here because millisecond normalization loses rates such as 24000/1001.
fn reduced_fps_from_probe(document: &ProbeDocument, stream: u32) -> Result<(u32, u32)> {
    let selected = document
        .streams
        .iter()
        .find(|candidate| candidate.index == stream && candidate.codec_type == "video")
        .ok_or_else(|| anyhow::anyhow!("invalid_media"))?;
    let (time_base_num, time_base_den) = parse_positive_rational(
        selected
            .time_base
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("invalid_media"))?,
    )?;
    let timestamps = document
        .frames
        .iter()
        .filter(|frame| frame.media_type == "video" && frame.stream_index == stream)
        .map(|frame| {
            frame
                .best_effort_timestamp
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("invalid_media"))?
                .parse()
        })
        .collect::<Result<Vec<_>>>()?;
    if timestamps.windows(2).any(|window| window[1] < window[0]) {
        bail!("invalid_media");
    }
    let mut deltas = timestamps
        .windows(2)
        .filter_map(|window| {
            i128::from(window[1])
                .checked_sub(i128::from(window[0]))
                .filter(|delta| *delta > 0)
                .and_then(|delta| u128::try_from(delta).ok())
        })
        .collect::<Vec<_>>();
    if deltas.is_empty() {
        return Ok((1, 1));
    }
    deltas.sort_unstable();
    let delta = deltas[deltas.len() / 2];
    let mut num = u128::from(time_base_den);
    let mut den = delta
        .checked_mul(u128::from(time_base_num))
        .ok_or_else(|| anyhow::anyhow!("invalid_media"))?;
    let mut a = num;
    let mut b = den;
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    num /= a.max(1);
    den /= a.max(1);
    if num > den.saturating_mul(24) {
        return Ok((24, 1));
    }
    Ok((
        u32::try_from(num).map_err(|_| anyhow::anyhow!("invalid_media"))?,
        u32::try_from(den).map_err(|_| anyhow::anyhow!("invalid_media"))?,
    ))
}

async fn dispatch_av_tool(
    kind: ToolKind,
    args: Value,
    ctx: &ToolCtx,
    runner: &dyn AvArgvRunner,
) -> Result<ToolOutput> {
    // Parse every semantic argument before source admission. A later invalid
    // interval/sampling/index must never leave a fetched or persisted source.
    let parsed = parse_semantic_args(&args, kind)?;
    if let Some(code) = ctx
        .media_availability
        .extraction_handoff_error(kind.wire_name())
    {
        bail!("{code}");
    }
    let Some(authority) = ctx.media_authority() else {
        bail!(
            "media_attachment_authority_unavailable: no session media authority for this context"
        );
    };
    // Resolve exactly the runtime authority required by this tool. Probe-only
    // audio inspection needs an approved standalone FFprobe; tools that launch
    // FFmpeg require the compatible pair and carry both approved paths.
    let approved_programs = if runner.requires_approved_runtime() {
        if kind == ToolKind::InspectAudio {
            Some((
                None,
                authority
                    .approved_ffprobe_runtime()
                    .map_err(admission_error)?,
            ))
        } else {
            let (ffmpeg, ffprobe) = authority
                .approved_av_runtime_pair()
                .map_err(admission_error)?;
            Some((Some(ffmpeg), ffprobe))
        }
    } else {
        None
    };
    let capability_generation = ctx.config.snapshot().host_capabilities.generation.max(1);
    let session_hex =
        crate::tool_media_authority::revalidator::hex::encode(&authority.subject().session_id);
    let admitted = authority
        .admit_nested_source(&session_hex, &parsed.source)
        .map_err(admission_error)?;
    let admitted = authority
        .persist_new_source(admitted, kind.source_media_kind(), capability_generation)
        .await
        .map_err(admission_error)?;
    let requested_interval = parsed.interval;
    let mut reservation = if matches!(kind, ToolKind::ExtractAudio | ToolKind::ExtractVideoClip) {
        let reserved_duration = requested_interval
            .as_ref()
            .map(|interval| interval.end.0.saturating_sub(interval.start.0))
            .unwrap_or(MAX_EXTRACTION_DURATION_MS);
        match authority
            .reserve_derivative(
                reserved_duration,
                MAX_PROCESS_STDOUT_BYTES as u64,
                kind == ToolKind::ExtractVideoClip,
            )
            .await
        {
            Ok(reservation) => Some(reservation),
            Err(error) => {
                if admitted.newly_created {
                    authority
                        .discard_new_source(&admitted)
                        .await
                        .map_err(admission_error)?;
                }
                return Err(admission_error(error));
            }
        }
    } else {
        None
    };
    let result: Result<ToolOutput> = async {
        if ctx.cancel.is_cancelled() {
            bail!("cancelled");
        }
        let (input_path, mut probe_temps) = runner::input_path_from_handle(&admitted.handle)?;
        let mut probe = probe_process(&input_path);
        if let Some((_, ffprobe)) = &approved_programs {
            probe.program = ffprobe.clone();
        }
        probe.temp_paths.append(&mut probe_temps);
        let probe_out = runner.run(&probe, &ctx.cancel).await?;
        authority.record_runner_call();
        if probe_out.stdout.len() > probe.stdout_limit
            || probe_out.stderr.len() > probe.stderr_limit
        {
            bail!("resource_limit");
        }
        let document = parse_probe_document(&probe_out.stdout)?;
        let duration = duration_ms(&document)?;
        let want = match kind {
            ToolKind::InspectAudio | ToolKind::ExtractAudio => "audio",
            ToolKind::InspectVideo | ToolKind::ExtractVideoClip => "video",
        };
        let stream = select_stream(
            &stream_candidates(&document, want),
            parsed.stream_index,
        )?;
        if want == "video" {
            let selected = document
                .streams
                .iter()
                .find(|candidate| candidate.index == stream)
                .ok_or_else(|| anyhow::anyhow!("invalid_media"))?;
            let (Some(width), Some(height)) = (selected.width, selected.height) else {
                bail!("invalid_media");
            };
            let policy = crate::config::media_budget::MediaResourcePolicy::default();
            let pixels = policy
                .checked_decoded_pixels(
                    crate::config::media_budget::MediaConstraintContext::default(),
                    u64::from(width),
                    u64::from(height),
                )
                .map_err(|_| anyhow::anyhow!("resource_limit"))?;
            policy
                .evaluate(crate::config::media_budget::MediaEvaluationRequest {
                    dimension: crate::config::media_budget::MediaDimension::AggregateDecodedPixelsPerRequest,
                    requested: Some(pixels),
                    current_scope: 0,
                    profile: None,
                    adapter_limit: None,
                    request_limit: None,
                })
                .map_err(|_| anyhow::anyhow!("resource_limit"))?;
        }
        let interval = match requested_interval {
            Some(interval) => {
                interval.validate_duration(duration)?;
                interval
            }
            None => Interval {
                start: Milliseconds(0),
                end: duration,
            },
        };
        if matches!(kind, ToolKind::ExtractAudio | ToolKind::ExtractVideoClip)
            && interval.end.0.saturating_sub(interval.start.0) > MAX_EXTRACTION_DURATION_MS
        {
            bail!("resource_limit");
        }
        let attachment_hex =
            SessionMediaAuthority::attachment_id_hex(&admitted.attachment.attachment_id);
        match kind {
            ToolKind::InspectAudio | ToolKind::InspectVideo => {
                let result = inspect_result(
                    kind,
                    &document,
                    stream,
                    duration,
                    &attachment_hex,
                    admitted.newly_created,
                    parsed.sampling,
                    &admitted.handle,
                    runner,
                    ctx,
                    authority,
                    capability_generation,
                    approved_programs
                        .as_ref()
                        .and_then(|(ffmpeg, _)| ffmpeg.as_ref()),
                )
                .await;
                result
            }
            ToolKind::ExtractAudio | ToolKind::ExtractVideoClip => {
                // Validate every probe-derived extraction parameter before
                // staging the immutable source bytes. Once a private source
                // path exists, ownership passes to the runner cleanup guard.
                let source_audio = match kind {
                    ToolKind::ExtractAudio => Some(
                        source_audio_caps(&document, Some(stream))?
                            .ok_or_else(|| anyhow::anyhow!("invalid_media"))?,
                    ),
                    ToolKind::ExtractVideoClip => source_audio_caps(&document, None)?,
                    _ => unreachable!("extraction branch contains extraction tools only"),
                };
                let fps = if kind == ToolKind::ExtractVideoClip {
                    Some(reduced_fps_from_probe(&document, stream)?)
                } else {
                    None
                };
                let (input_path, source_temp_paths) =
                    runner::input_path_from_handle(&admitted.handle)?;
                extract_result(
                    kind,
                    stream,
                    &interval,
                    &input_path,
                    &attachment_hex,
                    admitted.newly_created,
                    runner,
                    ctx,
                    authority,
                    reservation
                        .take()
                        .expect("extraction reserves before runner"),
                    source_audio,
                    fps,
                    source_temp_paths,
                    approved_programs
                        .as_ref()
                        .and_then(|(ffmpeg, _)| ffmpeg.as_ref()),
                )
                .await
            }
        }
    }
    .await;
    let mut result = result;
    if result.is_err()
        && let Some(reservation) = &reservation
        && let Err(error) = authority.abort_derivative(reservation).await
    {
        result = Err(admission_error(error));
    }
    if result.is_err() && admitted.newly_created {
        if let Err(error) = authority.discard_new_source(&admitted).await {
            result = Err(admission_error(error));
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn inspect_result(
    kind: ToolKind,
    document: &ProbeDocument,
    stream: u32,
    duration: Milliseconds,
    attachment_id: &str,
    newly_created: bool,
    sampling: Option<StoryboardMode>,
    handle: &crate::tool_media_authority::AdmittedHandle,
    runner: &dyn AvArgvRunner,
    ctx: &ToolCtx,
    authority: &SessionMediaAuthority,
    capability_generation: u64,
    approved_ffmpeg: Option<&PathBuf>,
) -> Result<ToolOutput> {
    let mut value = json!({
        "kind": kind.wire_name(),
        "attachment_id": attachment_id,
        "attachment_created": newly_created,
        "stream_index": stream,
        "duration_ms": duration.0,
        "streams": document.streams.iter().map(|stream| json!({
            "index": stream.index,
            "codec_type": stream.codec_type,
            "codec_name": stream.codec_name,
            "sample_rate": stream.sample_rate,
            "channels": stream.channels,
            "width": stream.width,
            "height": stream.height,
        })).collect::<Vec<_>>(),
    });
    let mut media_parts = Vec::new();
    let mut published = Vec::new();
    if kind == ToolKind::InspectVideo {
        let requested = storyboard_timestamps(
            &Interval {
                start: Milliseconds(0),
                end: duration,
            },
            sampling.unwrap_or(StoryboardMode::MaxFrames(8)),
        )?;
        let actual = selected_pts_ms(document, stream)?;
        let selected = select_storyboard_frames(&requested, &actual, None);
        let mut artifacts = Vec::with_capacity(selected.frames.len());
        published.reserve(selected.frames.len());
        for (artifact_index, frame) in selected.frames.iter().enumerate() {
            let reservation = match authority
                .reserve_derivative(1_000, MAX_PROCESS_STDOUT_BYTES as u64, true)
                .await
            {
                Ok(reservation) => reservation,
                Err(error) => {
                    rollback_storyboard(authority, published).await?;
                    return Err(admission_error(error));
                }
            };
            let mut publication_attempted = false;
            let produced: Result<(
                Value,
                crate::typed_media_result::MediaReference,
                crate::tool_media_authority::AdmittedAttachment,
            )> = async {
                if ctx.cancel.is_cancelled() {
                    bail!("cancelled");
                }
                let (input_path, source_temps) = runner::input_path_from_handle(handle)?;
                let mut spec = storyboard_frame_process(
                    &input_path,
                    stream,
                    Milliseconds(frame.actual_pts_ms),
                );
                if let Some(program) = approved_ffmpeg {
                    spec.program = program.clone();
                }
                spec.temp_paths.extend(source_temps);
                let out = runner.run(&spec, &ctx.cancel).await?;
                authority.record_runner_call();
                if ctx.cancel.is_cancelled() {
                    bail!("cancelled");
                }
                if out.stdout.is_empty()
                    || out.stdout.len() > spec.stdout_limit
                    || out.stderr.len() > spec.stderr_limit
                {
                    bail!("resource_limit");
                }
                let bytes = out.stdout;
                publication_attempted = true;
                let derivative = authority
                    .publish_owned_component(
                        &reservation,
                        cockpit_db::media_attachments::MediaSourceKind::ToolDerivative,
                        cockpit_db::media_attachments::MediaKind::Image,
                        "image/png",
                        bytes.clone(),
                        capability_generation,
                    )
                    .await
                    .map_err(admission_error)?;
                authority.record_reservation();
                let reference = crate::typed_media_result::MediaReference::new(
                    uuid::Uuid::from_bytes(derivative.attachment_id()),
                    derivative.attachment_version(),
                    crate::typed_media_result::CanonicalMediaKind::Image,
                    "image/png",
                    u32::try_from(artifact_index + 2)
                        .map_err(|_| anyhow::anyhow!("resource_limit"))?,
                    crate::typed_media_result::MediaReferencePurpose::Primary,
                    crate::intel::hex_lower(&derivative.checksum()),
                    bytes.len() as u64,
                    crate::typed_media_result::MediaReferenceAvailability::Ready,
                    crate::typed_media_result::MediaProvenance {
                        tool_name: kind.wire_name().to_owned(),
                        source_label: Some("storyboard-frame".into()),
                    },
                );
                Ok((
                    json!({
                        "requested_ms": frame.requested_ms,
                        "actual_pts_ms": frame.actual_pts_ms,
                        "reservation_id": &reservation.reservation_id,
                        "media_ordinal": artifact_index + 2,
                    }),
                    reference,
                    derivative,
                ))
            }
            .await;
            match produced {
                Ok((artifact, reference, derivative)) => {
                    if ctx.cancel.is_cancelled() {
                        published.push((reservation, derivative));
                        rollback_storyboard(authority, published).await?;
                        bail!("cancelled");
                    }
                    artifacts.push(artifact);
                    media_parts.push(
                        crate::typed_media_result::CanonicalToolResultContent::media_reference(
                            reference,
                        ),
                    );
                    published.push((reservation, derivative));
                }
                Err(error) => {
                    let abort = if publication_attempted {
                        Ok(())
                    } else {
                        authority
                            .abort_derivative(&reservation)
                            .await
                            .map_err(admission_error)
                    };
                    let rollback = rollback_storyboard(authority, published).await;
                    abort?;
                    rollback?;
                    return Err(error);
                }
            }
        }
        // Covers cancellation racing the final publication: no subsequent
        // iteration exists to observe it, so re-check before references leave
        // this ownership scope and compensate every published frame.
        if ctx.cancel.is_cancelled() {
            rollback_storyboard(authority, published).await?;
            bail!("cancelled");
        }
        value["storyboard"] = json!({
            "selection": selected,
            "artifacts": artifacts,
        });
    }
    let mut content = vec![crate::typed_media_result::CanonicalToolResultContent::json(
        value,
    )];
    content.extend(media_parts);
    let output = ToolOutput::canonical(content);
    if ctx.cancel.is_cancelled() {
        rollback_storyboard(authority, published).await?;
        bail!("cancelled");
    }
    match output {
        Ok(output) => Ok(output),
        Err(error) => {
            rollback_storyboard(authority, published).await?;
            Err(error)
        }
    }
}

async fn rollback_storyboard(
    authority: &SessionMediaAuthority,
    published: Vec<(
        crate::tool_media_authority::session_authority::DerivativeReservation,
        crate::tool_media_authority::AdmittedAttachment,
    )>,
) -> Result<()> {
    let mut first_error = None;
    for (reservation, attachment) in published.into_iter().rev() {
        if let Err(error) = authority
            .discard_published_derivative(&reservation, &attachment)
            .await
            && first_error.is_none()
        {
            first_error = Some(admission_error(error));
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn extract_result(
    kind: ToolKind,
    stream: u32,
    interval: &Interval,
    input_path: &str,
    attachment_id: &str,
    newly_created: bool,
    runner: &dyn AvArgvRunner,
    ctx: &ToolCtx,
    authority: &SessionMediaAuthority,
    reservation: crate::tool_media_authority::session_authority::DerivativeReservation,
    source_audio: Option<(u32, u32, u8)>,
    fps: Option<(u32, u32)>,
    source_temp_paths: Vec<PathBuf>,
    approved_ffmpeg: Option<&PathBuf>,
) -> Result<ToolOutput> {
    let mut spec = match kind {
        ToolKind::ExtractAudio => {
            let (_, rate, channels) =
                source_audio.expect("audio extraction validates its exact selected audio stream");
            audio_process(input_path, interval, stream, rate, channels)
        }
        ToolKind::ExtractVideoClip => {
            let (fps_num, fps_den) = fps.expect("video extraction validates PTS before staging");
            clip_process(input_path, interval, stream, source_audio, fps_num, fps_den)
        }
        _ => unreachable!("extract_result is extraction-only"),
    };
    if let Some(program) = approved_ffmpeg {
        spec.program = program.clone();
    }
    spec.temp_paths.extend(source_temp_paths);
    let out = match runner.run(&spec, &ctx.cancel).await {
        Ok(out) => out,
        Err(error) => {
            authority
                .abort_derivative(&reservation)
                .await
                .map_err(admission_error)?;
            return Err(error);
        }
    };
    authority.record_runner_call();
    if ctx.cancel.is_cancelled() {
        authority
            .abort_derivative(&reservation)
            .await
            .map_err(admission_error)?;
        bail!("cancelled");
    }
    if out.stdout.is_empty()
        || out.stdout.len() > spec.stdout_limit
        || out.stderr.len() > spec.stderr_limit
    {
        authority
            .abort_derivative(&reservation)
            .await
            .map_err(admission_error)?;
        bail!("resource_limit");
    }
    authority.record_reservation();
    let mime = match kind {
        ToolKind::ExtractAudio => "audio/wav",
        _ => "video/mp4",
    };
    let bytes = out.stdout;
    let media_kind = match kind {
        ToolKind::ExtractAudio => cockpit_db::media_attachments::MediaKind::Audio,
        _ => cockpit_db::media_attachments::MediaKind::Video,
    };
    let derivative = authority
        .publish_owned_component(
            &reservation,
            cockpit_db::media_attachments::MediaSourceKind::ToolDerivative,
            media_kind,
            mime,
            bytes.clone(),
            ctx.config.snapshot().host_capabilities.generation.max(1),
        )
        .await;
    let derivative = match derivative {
        Ok(derivative) => derivative,
        Err(error) => return Err(admission_error(error)),
    };
    if ctx.cancel.is_cancelled() {
        authority
            .discard_published_derivative(&reservation, &derivative)
            .await
            .map_err(admission_error)?;
        bail!("cancelled");
    }
    let derivative_id = uuid::Uuid::from_bytes(derivative.attachment_id());
    let checksum = crate::intel::hex_lower(&derivative.checksum());
    let reference = crate::typed_media_result::MediaReference::new(
        derivative_id,
        derivative.attachment_version(),
        match kind {
            ToolKind::ExtractAudio => crate::typed_media_result::CanonicalMediaKind::Audio,
            _ => crate::typed_media_result::CanonicalMediaKind::Video,
        },
        mime,
        2,
        crate::typed_media_result::MediaReferencePurpose::Primary,
        checksum,
        bytes.len() as u64,
        crate::typed_media_result::MediaReferenceAvailability::Ready,
        crate::typed_media_result::MediaProvenance {
            tool_name: kind.wire_name().to_string(),
            source_label: Some("av-derivative".into()),
        },
    )
    .with_duration_ms(interval.end.0.saturating_sub(interval.start.0));
    let output = ToolOutput::canonical(vec![
        crate::typed_media_result::CanonicalToolResultContent::json(json!({
            "kind": kind.wire_name(),
            "source_attachment_id": attachment_id,
            "attachment_created": newly_created,
            "reservation_id": &reservation.reservation_id,
            "media_ordinal": 2,
        })),
        crate::typed_media_result::CanonicalToolResultContent::media_reference(reference),
    ]);
    if ctx.cancel.is_cancelled() {
        authority
            .discard_published_derivative(&reservation, &derivative)
            .await
            .map_err(admission_error)?;
        bail!("cancelled");
    }
    match output {
        Ok(output) => Ok(output),
        Err(error) => {
            authority
                .discard_published_derivative(&reservation, &derivative)
                .await
                .map_err(admission_error)?;
            Err(error)
        }
    }
}

impl ToolKind {
    fn source_media_kind(self) -> cockpit_db::media_attachments::MediaKind {
        match self {
            Self::InspectAudio | Self::ExtractAudio => {
                cockpit_db::media_attachments::MediaKind::Audio
            }
            Self::InspectVideo | Self::ExtractVideoClip => {
                cockpit_db::media_attachments::MediaKind::Video
            }
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::InspectAudio => "inspect_audio",
            Self::InspectVideo => "inspect_video",
            Self::ExtractVideoClip => "extract_video_clip",
            Self::ExtractAudio => "extract_audio",
        }
    }
}

macro_rules! media_tool {
    ($name:ident, $wire:literal, $description:literal, $defensive:literal, $kind:expr, $effect:expr) => {
        pub struct $name {
            runner: Arc<dyn AvArgvRunner>,
        }
        impl $name {
            pub fn new() -> Self {
                Self {
                    runner: Arc::new(SystemAvArgvRunner),
                }
            }
            pub fn with_runner(runner: Arc<dyn AvArgvRunner>) -> Self {
                Self { runner }
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        #[async_trait]
        impl Tool for $name {
            fn name(&self) -> &str {
                $wire
            }
            fn description(&self) -> &str {
                $description
            }
            fn defensive_description(&self) -> Option<String> {
                Some($defensive.into())
            }
            fn effect(&self) -> ToolEffect {
                $effect
            }
            fn binary_requirements(&self) -> Vec<BinaryRequirement> {
                requirements($kind)
            }
            fn parameters(&self) -> Value {
                schema($kind)
            }
            fn honors_dispatch_cancel(&self) -> bool {
                true
            }
            async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
                dispatch_av_tool($kind, args, ctx, self.runner.as_ref()).await
            }
        }
    };
}

media_tool!(
    InspectAudioTool,
    "inspect_audio",
    "Inspect bounded metadata for one authorized audio source. First call uses source: {attachment_id|path|url}; later calls reuse source: {attachment_id}.",
    "Read safe, bounded metadata for one audio source: duration, streams, codecs, and channel layout. First call uses source: {attachment_id|path|url} and immediately creates a typed session attachment; later calls reuse source: {attachment_id}. Use it before extract_audio to confirm what a source contains. It is strictly read-only and never transcodes or downloads; the session attachment authority admits the source. Requires ffprobe.",
    ToolKind::InspectAudio,
    ToolEffect::ReadOnly
);
media_tool!(
    InspectVideoTool,
    "inspect_video",
    "Inspect metadata or create a deterministic storyboard for one authorized video source. First call uses source: {attachment_id|path|url}; later calls reuse source: {attachment_id}.",
    "Read safe, bounded metadata, or build a deterministic storyboard of frame timestamps, for one video source. First call uses source: {attachment_id|path|url} and immediately creates a typed session attachment; later calls reuse source: {attachment_id}. Use it before extract_video_clip to see the streams and choose an interval. It is read-only and never re-encodes; the storyboard frame count is capped and the source must be admitted by the session attachment authority. Requires a compatible ffmpeg and ffprobe pair.",
    ToolKind::InspectVideo,
    ToolEffect::ReadOnly
);
media_tool!(
    ExtractVideoClipTool,
    "extract_video_clip",
    "Create a bounded MP4 clip derivative from one authorized video source. First call uses source: {attachment_id|path|url}; later calls reuse source: {attachment_id}.",
    "Create one bounded MP4 clip derivative from a single video source, covering only the interval you request. First call uses source: {attachment_id|path|url} and immediately creates a typed session attachment; later calls reuse source: {attachment_id}. Use it after inspect_video has confirmed the stream and timing. This is a mutating operation: it writes a new derivative but never overwrites the original, and it refuses any source the session attachment authority has not admitted. Output resolution, frame rate, and duration are all bounded. Requires ffmpeg and ffprobe.",
    ToolKind::ExtractVideoClip,
    ToolEffect::Mutating
);
media_tool!(
    ExtractAudioTool,
    "extract_audio",
    "Create a bounded WAV derivative from one authorized audio or video source. First call uses source: {attachment_id|path|url}; later calls reuse source: {attachment_id}.",
    "Create one bounded WAV derivative from a single authorized audio or video source, capturing only the interval and stream you request. First call uses source: {attachment_id|path|url} and immediately creates a typed session attachment; later calls reuse source: {attachment_id}. Use it after inspecting the source to confirm its streams. This is a mutating operation: it writes a new derivative, never replaces the original, and rejects any source the session attachment authority has not admitted. Sample rate, channel count, and duration are all bounded. Requires ffmpeg and ffprobe.",
    ToolKind::ExtractAudio,
    ToolEffect::Mutating
);

#[cfg(test)]
mod tests;
