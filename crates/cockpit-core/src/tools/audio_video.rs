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
use sha2::{Digest, Sha256};

use crate::capabilities::{BinaryRequirement, CapabilityRemedy};
use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};
use crate::tool_media_authority::{AdmissionDenial, NestedMediaSource, SessionMediaAuthority};

mod runner;
pub use runner::{
    AvArgvRunner, AvRunnerOutput, DEFAULT_FFPROBE_JSON, DEFAULT_MP4_BYTES, DEFAULT_WAV_BYTES,
    FakeAvArgvRunner, RecordedAvRun, SystemAvArgvRunner,
};

pub const MAX_STORYBOARD_FRAMES: u32 = 64;
pub const DURATION_TOLERANCE_MS: u64 = 1;
pub const MAX_PROCESS_STDOUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PROCESS_STDERR_BYTES: usize = 64 * 1024;

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
    pub program: &'static str,
    pub argv: Vec<String>,
    pub environment: Vec<(&'static str, String)>,
    pub stdin_closed: bool,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
    pub deadline: Duration,
    pub temp_paths: Vec<PathBuf>,
    /// Files produced by the child that must be collected before cleanup.
    pub capture_files: Vec<PathBuf>,
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

/// Exact reduced fps rational from decoded PTS, capped at 24 fps and never
/// raised above the source rate.
pub fn reduced_fps_from_pts_ms(pts_ms: &[u64]) -> (u32, u32) {
    if pts_ms.len() < 2 {
        return (1, 1);
    }
    let mut deltas: Vec<u64> = pts_ms
        .windows(2)
        .map(|window| window[1].saturating_sub(window[0]))
        .filter(|delta| *delta > 0)
        .collect();
    if deltas.is_empty() {
        return (1, 1);
    }
    deltas.sort_unstable();
    let median = deltas[deltas.len() / 2].max(1);
    // fps = 1000/median, reduced; cap at 24/1 without upsampling.
    let mut num = 1_000u32;
    let mut den = u32::try_from(median).unwrap_or(u32::MAX).max(1);
    let divisor = gcd_u32(num, den);
    num /= divisor;
    den /= divisor;
    if u64::from(num) > u64::from(den).saturating_mul(24) {
        (24, 1)
    } else {
        (num, den)
    }
}

fn process_spec(program: &'static str, argv: Vec<String>, deadline: Duration) -> ProcessSpec {
    ProcessSpec {
        program,
        argv,
        environment: vec![("LC_ALL", "C".into()), ("LANG", "C".into())],
        stdin_closed: true,
        stdout_limit: MAX_PROCESS_STDOUT_BYTES,
        stderr_limit: MAX_PROCESS_STDERR_BYTES,
        deadline,
        temp_paths: Vec::new(),
        capture_files: Vec::new(),
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

pub fn clip_process(
    input: &str,
    output: &str,
    interval: &Interval,
    stream: u32,
    sample_rate: u32,
    channels: u8,
    fps_num: u32,
    fps_den: u32,
) -> ProcessSpec {
    let rate = sample_rate.min(48_000);
    let channels = channels.clamp(1, 2);
    let fps_den = fps_den.max(1);
    let (fps_num, fps_den) = {
        let divisor = gcd_u32(fps_num.max(1), fps_den);
        (fps_num.max(1) / divisor, fps_den / divisor)
    };
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
            "-map".into(),
            "0:a?".into(),
            "-vf".into(),
            format!(
                "scale='min(1280,iw)':'min(720,ih)':force_original_aspect_ratio=decrease,fps={fps_num}/{fps_den},format=yuv420p"
            ),
            "-c:v".into(),
            "libx264".into(),
            "-c:a".into(),
            "aac".into(),
            "-ar".into(),
            rate.to_string(),
            "-ac".into(),
            channels.to_string(),
            "-movflags".into(),
            "+faststart".into(),
            output.into(),
        ],
        Duration::from_secs(120),
    )
}

pub fn audio_process(
    input: &str,
    output: &str,
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
            output.into(),
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
    let remedy = CapabilityRemedy::prose("Install a compatible system FFmpeg/FFprobe pair.");
    let mut result = vec![BinaryRequirement::required("ffprobe", remedy.clone())];
    if kind != ToolKind::InspectAudio {
        result.push(BinaryRequirement::required("ffmpeg", remedy));
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
    best_effort_timestamp: Option<String>,
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
    Milliseconds::from_decimal_seconds(raw)
}

fn selected_pts_ms(document: &ProbeDocument, stream: u32) -> Result<Vec<Milliseconds>> {
    let mut pts = Vec::new();
    for frame in &document.frames {
        if frame.media_type != "video" || frame.stream_index != stream {
            continue;
        }
        if let Some(time) = frame.pts_time.as_deref() {
            pts.push(Milliseconds::from_decimal_seconds(time)?);
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

fn source_audio_caps(document: &ProbeDocument, stream: u32) -> Result<(u32, u8)> {
    let found = document
        .streams
        .iter()
        .find(|candidate| candidate.index == stream && candidate.codec_type == "audio")
        .or_else(|| {
            document
                .streams
                .iter()
                .find(|candidate| candidate.codec_type == "audio")
        });
    let Some(found) = found else {
        // A video-only clip has no audio stream to resample. These values are
        // inert because `0:a?` maps no audio in that case.
        return Ok((48_000, 2));
    };
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
    Ok((rate, channels))
}

async fn dispatch_av_tool(
    kind: ToolKind,
    args: Value,
    ctx: &ToolCtx,
    runner: &dyn AvArgvRunner,
) -> Result<ToolOutput> {
    validate_tool_args(&args, kind)?;
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
    let source = parse_nested_source(&args)?;
    let session_hex =
        crate::tool_media_authority::revalidator::hex::encode(&authority.subject().session_id);
    let admitted = authority
        .admit_nested_source(&session_hex, &source)
        .map_err(admission_error)?;
    if ctx.cancel.is_cancelled() {
        bail!("cancelled");
    }
    let (input_path, mut probe_temps) = runner::input_path_from_handle(&admitted.handle)?;
    let mut probe = probe_process(&input_path);
    probe.temp_paths.append(&mut probe_temps);
    let probe_out = runner.run(&probe, &ctx.cancel).await?;
    authority.record_runner_call();
    if probe_out.stdout.len() > probe.stdout_limit || probe_out.stderr.len() > probe.stderr_limit {
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
        args.get("stream_index")
            .and_then(Value::as_u64)
            .map(|v| v as u32),
    )?;
    let interval = match parse_optional_interval(&args)? {
        Some(interval) => {
            interval.validate_duration(duration)?;
            interval
        }
        None => Interval {
            start: Milliseconds(0),
            end: duration,
        },
    };
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
                parse_sampling(&args)?,
            );
            result
        }
        ToolKind::ExtractAudio | ToolKind::ExtractVideoClip => {
            let (input_path, source_temp_paths) = runner::input_path_from_handle(&admitted.handle)?;
            extract_result(
                kind,
                &document,
                stream,
                &interval,
                &input_path,
                &attachment_hex,
                admitted.newly_created,
                runner,
                ctx,
                authority,
                source_temp_paths,
            )
            .await
        }
    }
}

fn inspect_result(
    kind: ToolKind,
    document: &ProbeDocument,
    stream: u32,
    duration: Milliseconds,
    attachment_id: &str,
    newly_created: bool,
    sampling: Option<StoryboardMode>,
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
    if kind == ToolKind::InspectVideo {
        if let Some(mode) = sampling {
            let requested = storyboard_timestamps(
                &Interval {
                    start: Milliseconds(0),
                    end: duration,
                },
                mode,
            )?;
            let actual = selected_pts_ms(document, stream)?;
            let selected = select_storyboard_frames(&requested, &actual, None);
            value["storyboard"] = serde_json::to_value(selected)?;
        }
    }
    Ok(ToolOutput::text(value.to_string()))
}

#[allow(clippy::too_many_arguments)]
async fn extract_result(
    kind: ToolKind,
    document: &ProbeDocument,
    stream: u32,
    interval: &Interval,
    input_path: &str,
    attachment_id: &str,
    newly_created: bool,
    runner: &dyn AvArgvRunner,
    ctx: &ToolCtx,
    authority: &SessionMediaAuthority,
    source_temp_paths: Vec<PathBuf>,
) -> Result<ToolOutput> {
    let (rate, channels) = source_audio_caps(document, stream)?;
    let (output, output_dir) = runner::private_output_path(match kind {
        ToolKind::ExtractAudio => "wav",
        _ => "mp4",
    })?;
    let output_text = output.to_string_lossy().into_owned();
    let mut spec = match kind {
        ToolKind::ExtractAudio => {
            audio_process(input_path, &output_text, interval, stream, rate, channels)
        }
        ToolKind::ExtractVideoClip => {
            let pts = selected_pts_ms(document, stream)?
                .into_iter()
                .map(|ms| ms.0)
                .collect::<Vec<_>>();
            let (fps_num, fps_den) = reduced_fps_from_pts_ms(&pts);
            clip_process(
                input_path,
                &output_text,
                interval,
                stream,
                rate,
                channels,
                fps_num,
                fps_den,
            )
        }
        _ => unreachable!("extract_result is extraction-only"),
    };
    spec.capture_files.push(output.clone());
    spec.temp_paths.push(output);
    spec.temp_paths.push(output_dir);
    spec.temp_paths.extend(source_temp_paths);
    let out = runner.run(&spec, &ctx.cancel).await?;
    authority.record_runner_call();
    if out.stdout.len() > spec.stdout_limit || out.stderr.len() > spec.stderr_limit {
        bail!("resource_limit");
    }
    authority.record_reservation();
    let derivative_id = uuid::Uuid::now_v7();
    let mime = match kind {
        ToolKind::ExtractAudio => "audio/wav",
        _ => "video/mp4",
    };
    let bytes = out
        .captured_files
        .into_iter()
        .next()
        .map(|(_, bytes)| bytes)
        .ok_or_else(|| anyhow::anyhow!("media_derivative_missing"))?;
    let checksum = crate::intel::hex_lower(Sha256::digest(&bytes).as_slice());
    let reference = crate::typed_media_result::MediaReference::new(
        derivative_id,
        1,
        match kind {
            ToolKind::ExtractAudio => crate::typed_media_result::CanonicalMediaKind::Audio,
            _ => crate::typed_media_result::CanonicalMediaKind::Video,
        },
        mime,
        0,
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
    let content = crate::typed_media_result::CanonicalToolResultContent::media_reference(reference);
    Ok(ToolOutput::text(
        json!({
            "kind": kind.wire_name(),
            "source_attachment_id": attachment_id,
            "attachment_created": newly_created,
            "reservation_id": format!("res-{}", derivative_id),
            "result": content,
        })
        .to_string(),
    ))
}

impl ToolKind {
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
    "Read safe, bounded metadata, or build a deterministic storyboard of frame timestamps, for one video source. First call uses source: {attachment_id|path|url} and immediately creates a typed session attachment; later calls reuse source: {attachment_id}. Use it before extract_video_clip to see the streams and choose an interval. It is read-only and never re-encodes; the storyboard frame count is capped and the source must be admitted by the session attachment authority. Requires ffprobe.",
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
