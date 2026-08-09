//! Bounded audio/video inspection and extraction contracts.
//!
//! The executable boundary is deliberately attachment-ID based. Source URLs
//! and paths are admitted only by the session attachment authority; this
//! module never opens an arbitrary model-supplied path itself.

use anyhow::{Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::capabilities::{BinaryRequirement, CapabilityRemedy};
use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoryboardSelection {
    pub frames: Vec<StoryboardFrame>,
    pub sample_unavailable_ms: Vec<u64>,
    pub omitted_duplicates: Vec<StoryboardFrame>,
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
}

fn process_spec(program: &'static str, argv: Vec<String>) -> ProcessSpec {
    ProcessSpec {
        program,
        argv,
        environment: vec![("LC_ALL", "C".into()), ("LANG", "C".into())],
        stdin_closed: true,
        stdout_limit: MAX_PROCESS_STDOUT_BYTES,
        stderr_limit: MAX_PROCESS_STDERR_BYTES,
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
            "-of".into(),
            "json".into(),
            "--".into(),
            path.into(),
        ],
    )
}

pub fn clip_process(input: &str, output: &str, interval: &Interval, stream: u32) -> ProcessSpec {
    process_spec("ffmpeg", vec![
        "-nostdin".into(), "-v".into(), "error".into(), "-i".into(), input.into(),
        "-ss".into(), format!("{:.3}", interval.start.0 as f64 / 1_000.0),
        "-t".into(), format!("{:.3}", (interval.end.0 - interval.start.0) as f64 / 1_000.0),
        "-map".into(), format!("0:{stream}"), "-vf".into(),
        "scale='min(1280,iw)':'min(720,ih)':force_original_aspect_ratio=decrease,fps='min(24,source_fps)',format=yuv420p".into(),
        "-c:v".into(), "libx264".into(), "-c:a".into(), "aac".into(), "-ar".into(), "48000".into(),
        "-ac".into(), "2".into(), "-movflags".into(), "+faststart".into(), "--".into(), output.into(),
    ])
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
            format!("{:.3}", interval.start.0 as f64 / 1_000.0),
            "-t".into(),
            format!(
                "{:.3}",
                (interval.end.0 - interval.start.0) as f64 / 1_000.0
            ),
            "-map".into(),
            format!("0:{stream}"),
            "-vn".into(),
            "-c:a".into(),
            "pcm_s16le".into(),
            "-ar".into(),
            rate.to_string(),
            "-ac".into(),
            channels.to_string(),
            "--".into(),
            output.into(),
        ],
    )
}

fn source_schema() -> Value {
    json!({"oneOf": [
        {"required": ["attachment_id"], "properties": {"attachment_id": {"type": "string", "minLength": 1}}, "additionalProperties": true},
        {"required": ["path"], "properties": {"path": {"type": "string", "minLength": 1}}, "additionalProperties": true},
        {"required": ["url"], "properties": {"url": {"type": "string", "pattern": "^https://"}}, "additionalProperties": true}
    ]})
}

fn schema(kind: ToolKind) -> Value {
    let mut properties = serde_json::Map::new();
    properties.insert(
        "attachment_id".into(),
        json!({"type":"string","minLength":1}),
    );
    properties.insert("path".into(), json!({"type":"string","minLength":1}));
    properties.insert("url".into(), json!({"type":"string","pattern":"^https://"}));
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
        properties.insert("sampling".into(), json!({"oneOf":[
            {"type":"object","required":["every_seconds"],"properties":{"every_seconds":{"type":"number","exclusiveMinimum":0,"multipleOf":0.001}},"additionalProperties":false},
            {"type":"object","required":["max_frames"],"properties":{"max_frames":{"type":"integer","minimum":1,"maximum":MAX_STORYBOARD_FRAMES}},"additionalProperties":false}
        ]}));
    }
    json!({"type":"object","properties":properties,"allOf":[source_schema()],"additionalProperties":false})
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

async fn fail_closed(args: Value) -> Result<ToolOutput> {
    // Validate the mutually-exclusive source contract before reporting the
    // unavailable custody service, so malformed model calls stay invocation
    // failures rather than environmental failures.
    let sources = ["attachment_id", "path", "url"]
        .into_iter()
        .filter(|key| args.get(key).is_some())
        .count();
    if sources != 1 {
        return Err(invalid_input(
            "exactly one of attachment_id, path, or url is required",
        ));
    }
    bail!(
        "media_attachment_authority_unavailable: this repository does not yet expose the typed session attachment authority required for safe media execution"
    )
}

macro_rules! media_tool {
    ($name:ident, $wire:literal, $description:literal, $kind:expr, $effect:expr) => {
        pub struct $name;
        #[async_trait]
        impl Tool for $name {
            fn name(&self) -> &str {
                $wire
            }
            fn description(&self) -> &str {
                $description
            }
            fn defensive_description(&self) -> Option<String> {
                Some($description.into())
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
            async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
                fail_closed(args).await
            }
        }
    };
}

media_tool!(
    InspectAudioTool,
    "inspect_audio",
    "Inspect bounded metadata for one authorized audio attachment.",
    ToolKind::InspectAudio,
    ToolEffect::ReadOnly
);
media_tool!(
    InspectVideoTool,
    "inspect_video",
    "Inspect metadata or create a deterministic storyboard for one authorized video attachment.",
    ToolKind::InspectVideo,
    ToolEffect::ReadOnly
);
media_tool!(
    ExtractVideoClipTool,
    "extract_video_clip",
    "Create a bounded MP4 clip derivative from one authorized video attachment.",
    ToolKind::ExtractVideoClip,
    ToolEffect::Mutating
);
media_tool!(
    ExtractAudioTool,
    "extract_audio",
    "Create a bounded WAV derivative from one authorized audio or video attachment.",
    ToolKind::ExtractAudio,
    ToolEffect::Mutating
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_video_storyboard_timestamps_are_exact_and_end_exclusive() {
        let interval = Interval::checked(Milliseconds(1_000), Milliseconds(2_001)).unwrap();
        assert_eq!(
            storyboard_timestamps(&interval, StoryboardMode::Every(Milliseconds(500))).unwrap(),
            vec![
                Milliseconds(1_000),
                Milliseconds(1_500),
                Milliseconds(2_000)
            ]
        );
        assert_eq!(
            storyboard_timestamps(&interval, StoryboardMode::MaxFrames(3)).unwrap(),
            vec![
                Milliseconds(1_000),
                Milliseconds(1_500),
                Milliseconds(2_000)
            ]
        );
    }

    #[test]
    fn audio_video_stream_matrix_uses_default_then_lowest() {
        let streams = vec![
            StreamCandidate {
                index: 1,
                disposition_default: false,
                allowed: true,
            },
            StreamCandidate {
                index: 3,
                disposition_default: true,
                allowed: true,
            },
            StreamCandidate {
                index: 2,
                disposition_default: true,
                allowed: true,
            },
        ];
        assert_eq!(select_stream(&streams, None).unwrap(), 2);
        assert_eq!(select_stream(&streams, Some(1)).unwrap(), 1);
    }

    #[test]
    fn audio_video_storyboard_deduplicates_and_applies_dynamic_tolerance() {
        let selected = select_storyboard_frames(
            &[Milliseconds(0), Milliseconds(5), Milliseconds(400)],
            &[Milliseconds(90), Milliseconds(550)],
            Some(240),
        );
        assert_eq!(
            selected.frames,
            vec![StoryboardFrame {
                requested_ms: 0,
                actual_pts_ms: 90
            }]
        );
        assert_eq!(selected.omitted_duplicates.len(), 1);
        assert_eq!(selected.sample_unavailable_ms, vec![400]);
        assert_eq!(frame_tolerance_ms(Some(2_000)), 500);
    }

    #[test]
    fn audio_video_process_specs_are_argv_only_and_capped() {
        let spec = probe_process("name; touch nope");
        assert_eq!(spec.program, "ffprobe");
        assert_eq!(spec.argv.last().unwrap(), "name; touch nope");
        assert!(spec.stdin_closed);
        assert_eq!(spec.environment.len(), 2);
        assert!(spec.stdout_limit > spec.stderr_limit);
    }
}
