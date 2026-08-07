//! Cross-language transport fixtures.
//!
//! Rust is the source of truth: every vector here is produced by the real
//! codecs in `cockpit_proto::remote_transport` and written to
//! `packages/cockpit-protocol/fixtures/remote-transport/`. The TypeScript
//! mirror in `packages/cockpit-protocol/src/remote-transport-lanes.test.ts`
//! consumes the very same files, so neither side can drift without the other
//! failing. There are no duplicated literals across the two languages.
//!
//! Regenerate from the repository root with:
//!
//! ```sh
//! COCKPIT_UPDATE_GOLDEN=1 cargo test -p cockpit-proto --test remote_transport_fixtures
//! ```

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use cockpit_proto::remote_protocol_id::{
    RemoteFrameId, RemoteTransferId, encode_protocol_id_base64url, kind, tag_protocol_id_bytes,
};
use cockpit_proto::remote_transport::bulk::{
    BULK_ABORT_BYTES, BULK_BEGIN_BYTES_WITH_OPTIONS, BULK_BEGIN_BYTES_WITHOUT_OPTIONS,
    BULK_CHUNK_ENVELOPE_BYTES, BULK_COMPLETE_BYTES, BULK_OPTION_BITS_KNOWN,
    BULK_OPTION_BITS_UNKNOWN, MAX_BULK_CHUNK_PAYLOAD_BYTES, MAX_RECEIVER_WINDOW_BYTES,
    MAX_TRANSFER_BYTES, RemoteBulkAbort, RemoteBulkAbortReason, RemoteBulkBegin, RemoteBulkChunk,
    RemoteBulkComplete, RemoteBulkMessage, RemoteBulkMimeClass,
};
use cockpit_proto::remote_transport::channel::REMOTE_LANE_CHANNELS;
use cockpit_proto::remote_transport::classification::{
    EVENT_CLASSIFICATION, OVERSIZED_MESSAGE_INVENTORY, REQUEST_CLASSIFICATION,
    RESPONSE_CLASSIFICATION, RemoteMessageClass, RemoteMessageClassification, RemoteMessageKind,
    UNKNOWN_MESSAGE_TAG,
};
use cockpit_proto::remote_transport::fragment::{
    LANE_FRAGMENT_TOTAL_BYTES, MAX_FRAGMENT_COUNT, MAX_INCOMPLETE_FRAMES_PER_PEER,
    MAX_REASSEMBLY_BYTES_PER_PEER, NOISE_AEAD_TAG_BYTES, NOISE_MAX_PLAINTEXT_BYTES,
    NOISE_RECORD_HEADER_BYTES, NOISE_RECORD_MAX_CIPHERTEXT_BYTES, NOISE_RECORD_PAYLOAD_BYTES,
    PEER_SEEN_THROUGH_WATERMARK_BYTES, REASSEMBLY_DEADLINE_MS,
    REMOTE_CARRIER_FRAGMENT_HEADER_BYTES, REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES,
    REMOTE_CARRIER_FRAGMENT_VERSION, RemoteFragmentFlags, RemoteFragmentReassembler,
    fragment_frame,
};
use cockpit_proto::remote_transport::frame::{
    MAX_SERIALIZED_FRAME_BYTES, REMOTE_TRANSPORT_FRAME_HEADER_BYTES,
    REMOTE_TRANSPORT_FRAME_VERSION, RemoteFrameFlags, RemoteStreamOrigin, RemoteTransportFrameV1,
};
use cockpit_proto::remote_transport::lane::{MAX_LOGICAL_PAYLOAD_BYTES, RemoteLane};
use cockpit_proto::remote_transport::scheduler::{LANE_SCHEDULE, RemoteQueueLimits};

const FIXTURE_DIR: &str = "../../packages/cockpit-protocol/fixtures/remote-transport";
const UPDATE_ENV: &str = "COCKPIT_UPDATE_GOLDEN";

/// Full `encodedHex` is only inlined for vectors at or below this size; larger
/// vectors carry their header, digest, and length instead so the fixture files
/// stay reviewable.
const INLINE_HEX_LIMIT: usize = 512;

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_DIR)
}

fn update_fixtures() -> bool {
    std::env::var(UPDATE_ENV).is_ok()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

// --- Biome-compatible JSON rendering ---------------------------------------
//
// `pnpm check:ci` formats every JSON file in the repo. Biome follows
// Prettier's rules: an object written expanded stays expanded, and an array
// collapses onto one line when it holds no objects/arrays and fits the
// 100-column budget. Emitting exactly that keeps the fixtures format-stable
// without needing biome on the path.

const LINE_WIDTH: usize = 100;

fn render_json(value: &Value) -> String {
    let mut out = String::new();
    render_value(value, 0, &mut out);
    out.push('\n');
    out
}

fn render_value(value: &Value, indent: usize, out: &mut String) {
    match value {
        Value::Object(map) => render_object(map, indent, out),
        Value::Array(items) => render_array(items, indent, out),
        other => out.push_str(&scalar(other)),
    }
}

fn scalar(value: &Value) -> String {
    serde_json::to_string(value).expect("scalar serializes")
}

fn render_object(map: &Map<String, Value>, indent: usize, out: &mut String) {
    if map.is_empty() {
        out.push_str("{}");
        return;
    }
    // Objects are always expanded, matching the generator style already used by
    // the daemon-wire fixtures.
    out.push_str("{\n");
    let inner = indent + 2;
    for (i, (key, value)) in map.iter().enumerate() {
        out.push_str(&" ".repeat(inner));
        out.push_str(&scalar(&Value::String(key.clone())));
        out.push_str(": ");
        render_value(value, inner, out);
        if i + 1 < map.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(&" ".repeat(indent));
    out.push('}');
}

fn render_array(items: &[Value], indent: usize, out: &mut String) {
    if items.is_empty() {
        out.push_str("[]");
        return;
    }
    let composite = items
        .iter()
        .any(|item| matches!(item, Value::Object(_) | Value::Array(_)));
    if !composite {
        let single = format!(
            "[{}]",
            items.iter().map(scalar).collect::<Vec<_>>().join(", ")
        );
        if indent + single.len() <= LINE_WIDTH {
            out.push_str(&single);
            return;
        }
    }
    out.push_str("[\n");
    let inner = indent + 2;
    for (i, item) in items.iter().enumerate() {
        out.push_str(&" ".repeat(inner));
        render_value(item, inner, out);
        if i + 1 < items.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(&" ".repeat(indent));
    out.push(']');
}

/// Write the fixture when updating, otherwise assert the checked-in fixture
/// still describes exactly what the codecs produce.
///
/// The comparison is over parsed JSON, not raw bytes. Whitespace is owned by
/// biome (`pnpm check:ci` formats every JSON file in the repo), and a
/// hand-rolled pretty-printer that has to agree with biome byte for byte is a
/// standing source of false failures. What must not drift is the *content* —
/// every hex vector, length, and offset in here — and that is what this
/// compares. Formatting drift is caught by biome, where it belongs.
fn sync_fixture(name: &str, value: &Value) {
    let path = fixture_root().join(name);
    if update_fixtures() {
        std::fs::create_dir_all(fixture_root()).expect("create fixture dir");
        std::fs::write(&path, render_json(value).as_bytes())
            .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
        format_fixture_json(&path);
        return;
    }
    let existing = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "read {}: {error} — regenerate with {UPDATE_ENV}=1 cargo test -p cockpit-proto --test remote_transport_fixtures",
            path.display()
        )
    });
    let checked_in: Value = serde_json::from_str(&existing)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
    assert_eq!(
        &checked_in,
        value,
        "{} drifted; regenerate with {UPDATE_ENV}=1 cargo test -p cockpit-proto --test remote_transport_fixtures",
        path.display()
    );
}

/// Hand the freshly written fixture to biome so its formatting matches every
/// other JSON file in the repo. Update-mode only, so CI never needs biome.
fn format_fixture_json(path: &Path) {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let executable = if cfg!(windows) { "biome.cmd" } else { "biome" };
    let local = workspace_root
        .join("node_modules")
        .join(".bin")
        .join(executable);
    let biome = if local.is_file() {
        local
    } else {
        PathBuf::from(executable)
    };
    match std::process::Command::new(&biome)
        .args(["format", "--write"])
        .arg(path)
        .current_dir(&workspace_root)
        .status()
    {
        Ok(status) if status.success() => {}
        // Regeneration still succeeds without biome on PATH; `pnpm check:ci`
        // is the gate that would notice, and it always has biome.
        Ok(status) => eprintln!("biome format exited with {status} for {}", path.display()),
        Err(error) => eprintln!("biome format unavailable ({error}); skipping"),
    }
}

fn frame_id(seed: u8) -> RemoteFrameId {
    let mut bytes = [0u8; 16];
    for (i, slot) in bytes.iter_mut().enumerate() {
        *slot = seed.wrapping_add(i as u8).wrapping_add(1);
    }
    tag_protocol_id_bytes::<kind::Frame>(bytes).expect("nonzero frame id")
}

fn transfer_id(seed: u8) -> RemoteTransferId {
    let mut bytes = [0u8; 16];
    for (i, slot) in bytes.iter_mut().enumerate() {
        *slot = seed.wrapping_mul(3).wrapping_add(i as u8).wrapping_add(1);
    }
    tag_protocol_id_bytes::<kind::Transfer>(bytes).expect("nonzero transfer id")
}

/// A payload described generatively so both languages can rebuild it byte for
/// byte without a megabyte of hex in the fixture.
fn payload_spec(fill: u8, length: usize) -> Value {
    json!({ "fill": fill, "length": length })
}

fn build_payload(fill: u8, length: usize) -> Vec<u8> {
    vec![fill; length]
}

// --- fixture builders -------------------------------------------------------

fn constants_fixture() -> Value {
    let limits = RemoteQueueLimits::DEFAULT;
    json!({
        "_comment": "Generated by cockpit-proto's remote_transport_fixtures test. Do not hand edit.",
        "ndjsonMaxFrameBytes": cockpit_proto::MAX_NDJSON_FRAME_BYTES,
        "frame": {
            "version": REMOTE_TRANSPORT_FRAME_VERSION,
            "headerBytes": REMOTE_TRANSPORT_FRAME_HEADER_BYTES,
            "maxLogicalPayloadBytes": MAX_LOGICAL_PAYLOAD_BYTES,
            "maxSerializedFrameBytes": MAX_SERIALIZED_FRAME_BYTES,
            "offsets": {
                "version": 0, "lane": 1, "flags": 2, "streamId": 4, "streamSeq": 12,
                "frameId": 20, "payloadLength": 36, "payloadDigest": 40, "payload": 72
            },
            "flags": {
                "endStream": RemoteFrameFlags::END_STREAM,
                "resetStream": RemoteFrameFlags::RESET_STREAM,
                "defined": RemoteFrameFlags::DEFINED
            }
        },
        "lanes": RemoteLane::ALL.iter().map(|lane| json!({
            "lane": lane.as_str(),
            "laneId": lane.lane_id(),
            "maxPayloadBytes": lane.max_payload_bytes()
        })).collect::<Vec<_>>(),
        "fragment": {
            "version": REMOTE_CARRIER_FRAGMENT_VERSION,
            "headerBytes": REMOTE_CARRIER_FRAGMENT_HEADER_BYTES,
            "maxPayloadBytes": REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES,
            "maxFragmentCount": MAX_FRAGMENT_COUNT,
            "laneFragmentTotalBytes": LANE_FRAGMENT_TOTAL_BYTES,
            "offsets": {
                "version": 0, "lane": 1, "flags": 2, "frameId": 4,
                "fragmentIndex": 20, "fragmentCount": 22, "fragmentPayloadLength": 24,
                "bytes": 26
            },
            "flags": { "end": RemoteFragmentFlags::END, "defined": RemoteFragmentFlags::DEFINED }
        },
        "noise": {
            "recordMaxCiphertextBytes": NOISE_RECORD_MAX_CIPHERTEXT_BYTES,
            "aeadTagBytes": NOISE_AEAD_TAG_BYTES,
            "maxPlaintextBytes": NOISE_MAX_PLAINTEXT_BYTES,
            "recordHeaderBytes": NOISE_RECORD_HEADER_BYTES,
            "recordPayloadBytes": NOISE_RECORD_PAYLOAD_BYTES,
            "peerSeenThroughWatermarkBytes": PEER_SEEN_THROUGH_WATERMARK_BYTES
        },
        "reassembly": {
            "maxIncompleteFramesPerPeer": MAX_INCOMPLETE_FRAMES_PER_PEER,
            "maxBytesPerPeer": MAX_REASSEMBLY_BYTES_PER_PEER,
            "deadlineMs": REASSEMBLY_DEADLINE_MS
        },
        "bulk": {
            "kinds": { "begin": 1, "chunk": 2, "complete": 3, "abort": 4 },
            "optionBits": { "unknown": BULK_OPTION_BITS_UNKNOWN, "known": BULK_OPTION_BITS_KNOWN },
            "beginBytesWithoutOptions": BULK_BEGIN_BYTES_WITHOUT_OPTIONS,
            "beginBytesWithOptions": BULK_BEGIN_BYTES_WITH_OPTIONS,
            "chunkEnvelopeBytes": BULK_CHUNK_ENVELOPE_BYTES,
            "completeBytes": BULK_COMPLETE_BYTES,
            "abortBytes": BULK_ABORT_BYTES,
            "maxChunkPayloadBytes": MAX_BULK_CHUNK_PAYLOAD_BYTES,
            "maxReceiverWindowBytes": MAX_RECEIVER_WINDOW_BYTES.to_string(),
            "maxTransferBytes": MAX_TRANSFER_BYTES.to_string(),
            "mimeClasses": RemoteBulkMimeClass::ALL.iter().map(|class| json!({
                "name": class.as_str(),
                "code": class.code(),
                "maxTotalLength": class.max_total_length().to_string()
            })).collect::<Vec<_>>(),
            "abortReasons": RemoteBulkAbortReason::ALL.iter().map(|reason| json!({
                "name": reason.as_str(),
                "code": reason.code()
            })).collect::<Vec<_>>()
        },
        "queueLimits": {
            "controlFrames": limits.control_frames,
            "controlBytes": limits.control_bytes,
            "interactiveFrames": limits.interactive_frames,
            "interactiveBytes": limits.interactive_bytes,
            "bulkFrames": limits.bulk_frames,
            "bulkBytes": limits.bulk_bytes,
            "aggregateBytes": limits.aggregate_bytes,
            "controlReservedBytes": limits.control_reserved_bytes,
            "controlReservedFrames": limits.control_reserved_frames,
            "interactiveReservedBytes": limits.interactive_reserved_bytes,
            "sharedPoolBytes": limits.shared_pool_bytes()
        },
        "laneSchedule": LANE_SCHEDULE.iter().map(|lane| lane.as_str()).collect::<Vec<_>>()
    })
}

fn channels_fixture() -> Value {
    json!({
        "_comment": "Generated by cockpit-proto's remote_transport_fixtures test. Do not hand edit.",
        "channels": REMOTE_LANE_CHANNELS.iter().map(|channel| json!({
            "lane": channel.lane.as_str(),
            "laneId": channel.lane.lane_id(),
            "channelId": channel.channel_id,
            "label": channel.label,
            "negotiated": channel.negotiated,
            "ordered": channel.ordered,
            "reliable": channel.reliable,
            "compressed": channel.compressed,
            "maxPayloadBytes": channel.max_payload_bytes
        })).collect::<Vec<_>>()
    })
}

fn classification_rows(table: &'static [RemoteMessageClassification]) -> Vec<Value> {
    table
        .iter()
        .map(|row| {
            json!({
                "tag": row.tag,
                "class": row.class.as_str(),
                "lane": row.lane().as_str(),
                "inlinePayloadBound": row.inline_payload_bound.as_str()
            })
        })
        .collect()
}

fn classification_fixture() -> Value {
    json!({
        "_comment": "Generated from the Rust request/response/event variant tables. Do not hand edit.",
        "unknownMessageTag": UNKNOWN_MESSAGE_TAG,
        "classLanes": RemoteMessageClass::ALL.iter().map(|class| json!({
            "class": class.as_str(),
            "lane": class.lane().as_str()
        })).collect::<Vec<_>>(),
        "counts": {
            "request": REQUEST_CLASSIFICATION.len(),
            "response": RESPONSE_CLASSIFICATION.len(),
            "event": EVENT_CLASSIFICATION.len()
        },
        "messages": {
            "request": classification_rows(REQUEST_CLASSIFICATION),
            "response": classification_rows(RESPONSE_CLASSIFICATION),
            "event": classification_rows(EVENT_CLASSIFICATION)
        },
        "oversizedInventory": OVERSIZED_MESSAGE_INVENTORY.iter().map(|(kind, tag)| json!({
            "kind": kind.as_str(),
            "tag": tag
        })).collect::<Vec<_>>()
    })
}

struct FrameCase {
    name: &'static str,
    lane: RemoteLane,
    flags: RemoteFrameFlags,
    stream_id: u64,
    stream_seq: u64,
    frame_id: RemoteFrameId,
    fill: u8,
    length: usize,
}

fn frame_cases() -> Vec<FrameCase> {
    vec![
        FrameCase {
            name: "control_empty_payload",
            lane: RemoteLane::Control,
            flags: RemoteFrameFlags::empty(),
            stream_id: 0,
            stream_seq: 0,
            frame_id: frame_id(0x10),
            fill: 0,
            length: 0,
        },
        FrameCase {
            name: "control_end_stream",
            lane: RemoteLane::Control,
            flags: RemoteFrameFlags::empty().with_end_stream(),
            stream_id: 0,
            stream_seq: 1,
            frame_id: frame_id(0x20),
            fill: 0xC3,
            length: 16,
        },
        FrameCase {
            name: "interactive_client_stream_reset",
            lane: RemoteLane::Interactive,
            flags: RemoteFrameFlags::empty().with_reset_stream(),
            stream_id: 2,
            stream_seq: 0,
            frame_id: frame_id(0x30),
            fill: 0x5A,
            length: 64,
        },
        FrameCase {
            name: "interactive_daemon_stream_high_values",
            lane: RemoteLane::Interactive,
            flags: RemoteFrameFlags::empty(),
            // Exercises the full u64 range and network byte order.
            stream_id: 0xFFFF_FFFF_FFFF_FFFF,
            stream_seq: 0x0102_0304_0506_0708,
            frame_id: frame_id(0x40),
            fill: 0x11,
            length: 3,
        },
        FrameCase {
            name: "bulk_maximal_payload",
            lane: RemoteLane::Bulk,
            flags: RemoteFrameFlags::empty().with_end_stream(),
            stream_id: 4,
            stream_seq: 9,
            frame_id: frame_id(0x50),
            fill: 0xAB,
            length: MAX_LOGICAL_PAYLOAD_BYTES,
        },
        FrameCase {
            name: "control_maximal_payload",
            lane: RemoteLane::Control,
            flags: RemoteFrameFlags::empty(),
            stream_id: 0,
            stream_seq: 2,
            frame_id: frame_id(0x60),
            fill: 0x07,
            length: RemoteLane::Control.max_payload_bytes(),
        },
    ]
}

fn frames_fixture() -> Value {
    let cases = frame_cases()
        .into_iter()
        .map(|case| {
            let payload = build_payload(case.fill, case.length);
            let frame = RemoteTransportFrameV1::new(
                case.lane,
                case.stream_id,
                case.stream_seq,
                case.frame_id,
                payload,
            )
            .expect("frame within lane cap")
            .with_flags(case.flags);
            let encoded = frame.encode().expect("frame encodes");
            let mut row = json!({
                "name": case.name,
                "lane": case.lane.as_str(),
                "laneId": case.lane.lane_id(),
                "flags": case.flags.bits(),
                // CanonicalU64DecimalStringV1: u64 is never a JSON number.
                "streamId": case.stream_id.to_string(),
                "streamSeq": case.stream_seq.to_string(),
                "frameId": encode_protocol_id_base64url(case.frame_id.as_bytes()).unwrap(),
                "payload": payload_spec(case.fill, case.length),
                "payloadDigestHex": hex(&frame.payload_digest()),
                "headerHex": hex(&encoded[..REMOTE_TRANSPORT_FRAME_HEADER_BYTES]),
                "serializedLength": encoded.len()
            });
            if encoded.len() <= INLINE_HEX_LIMIT {
                row.as_object_mut()
                    .unwrap()
                    .insert("encodedHex".to_string(), json!(hex(&encoded)));
            }
            row
        })
        .collect::<Vec<_>>();
    json!({
        "_comment": "Generated by cockpit-proto's remote_transport_fixtures test. Do not hand edit.",
        "cases": cases
    })
}

fn fragments_fixture() -> Value {
    // The maximal frame is the interesting one: 524,360 bytes split into
    // exactly nine fragments, eight of them the full 65,471 bytes.
    let cases = [
        (
            "single_fragment_control",
            RemoteLane::Control,
            0u64,
            0x70u8,
            0usize,
            32usize,
        ),
        (
            "two_fragment_interactive",
            RemoteLane::Interactive,
            2,
            0x80,
            0,
            70_000,
        ),
        (
            "nine_fragment_maximal_bulk",
            RemoteLane::Bulk,
            4,
            0x90,
            0,
            MAX_LOGICAL_PAYLOAD_BYTES,
        ),
    ]
    .into_iter()
    .map(|(name, lane, stream_id, seed, fill, length)| {
        let id = frame_id(seed);
        let frame =
            RemoteTransportFrameV1::new(lane, stream_id, 0, id, build_payload(fill as u8, length))
                .expect("frame within lane cap");
        let serialized = frame.encode().expect("frame encodes");
        let fragments = fragment_frame(lane, id, &serialized).expect("fragments");

        // Prove the fixture really round-trips through reassembly.
        let mut reassembler = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        let mut rebuilt = None;
        for fragment in &fragments {
            if let Some(done) = reassembler.accept(fragment, 0).expect("accept") {
                rebuilt = Some(done);
            }
        }
        assert_eq!(rebuilt.as_ref(), Some(&frame));

        let rows = fragments
            .iter()
            .map(|fragment| {
                let encoded = fragment.encode().expect("fragment encodes");
                let mut row = json!({
                    "index": fragment.fragment_index,
                    "count": fragment.fragment_count,
                    "flags": fragment.flags.bits(),
                    "payloadLength": fragment.bytes.len(),
                    "encodedLength": encoded.len(),
                    "headerHex": hex(&encoded[..REMOTE_CARRIER_FRAGMENT_HEADER_BYTES])
                });
                if encoded.len() <= INLINE_HEX_LIMIT {
                    row.as_object_mut()
                        .unwrap()
                        .insert("encodedHex".to_string(), json!(hex(&encoded)));
                }
                row
            })
            .collect::<Vec<_>>();

        json!({
            "name": name,
            "lane": lane.as_str(),
            "streamId": stream_id.to_string(),
            "frameId": encode_protocol_id_base64url(id.as_bytes()).unwrap(),
            "payload": payload_spec(fill as u8, length),
            "serializedFrameLength": serialized.len(),
            "fragmentCount": fragments.len(),
            "fragments": rows
        })
    })
    .collect::<Vec<_>>();

    json!({
        "_comment": "Generated by cockpit-proto's remote_transport_fixtures test. Do not hand edit. WebRTC and the WebSocket fallback carry these bytes identically.",
        "cases": cases
    })
}

fn bulk_fixture() -> Value {
    let tid = transfer_id(1);
    let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
    let digest = cockpit_proto::remote_transport::frame::payload_digest(&payload);

    let messages = vec![
        (
            "begin_unknown_length",
            RemoteBulkMessage::Begin(RemoteBulkBegin::unknown_length(
                tid,
                RemoteBulkMimeClass::Opaque,
            )),
        ),
        (
            "begin_known_prehashed",
            RemoteBulkMessage::Begin(RemoteBulkBegin::known_length(
                tid,
                RemoteBulkMimeClass::Archive,
                payload.len() as u64,
                digest,
            )),
        ),
        (
            "begin_image_class",
            RemoteBulkMessage::Begin(RemoteBulkBegin::unknown_length(
                tid,
                RemoteBulkMimeClass::Image,
            )),
        ),
        (
            "chunk_first",
            RemoteBulkMessage::Chunk(RemoteBulkChunk {
                transfer_id: tid,
                chunk_index: 0,
                offset: 0,
                bytes: payload.clone(),
            }),
        ),
        (
            "chunk_offset_high",
            RemoteBulkMessage::Chunk(RemoteBulkChunk {
                transfer_id: tid,
                chunk_index: 0x0102_0304,
                offset: 0x0506_0708_090A_0B0C,
                bytes: b"tail".to_vec(),
            }),
        ),
        (
            "complete",
            RemoteBulkMessage::Complete(RemoteBulkComplete {
                transfer_id: tid,
                final_length: payload.len() as u64,
                sha256: digest,
            }),
        ),
        (
            "abort_cancelled",
            RemoteBulkMessage::Abort(RemoteBulkAbort {
                transfer_id: tid,
                reason: RemoteBulkAbortReason::Cancelled,
            }),
        ),
        (
            "abort_integrity_failure",
            RemoteBulkMessage::Abort(RemoteBulkAbort {
                transfer_id: tid,
                reason: RemoteBulkAbortReason::IntegrityFailure,
            }),
        ),
    ];

    let cases = messages
        .into_iter()
        .map(|(name, message)| {
            let encoded = message.encode().expect("bulk message encodes");
            assert_eq!(
                RemoteBulkMessage::decode(&encoded).expect("round trip"),
                message
            );
            json!({
                "name": name,
                "encodedHex": hex(&encoded),
                "encodedLength": encoded.len()
            })
        })
        .collect::<Vec<_>>();

    // A maximal chunk: header plus 524,255 bytes exactly fills the lane cap.
    let maximal = RemoteBulkMessage::Chunk(RemoteBulkChunk {
        transfer_id: tid,
        chunk_index: 0,
        offset: 0,
        bytes: build_payload(0x5A, MAX_BULK_CHUNK_PAYLOAD_BYTES),
    });
    let maximal_encoded = maximal.encode().expect("maximal chunk encodes");

    json!({
        "_comment": "Generated by cockpit-proto's remote_transport_fixtures test. Do not hand edit.",
        "transferId": encode_protocol_id_base64url(tid.as_bytes()).unwrap(),
        "payloadUtf8": String::from_utf8(payload).unwrap(),
        "payloadDigestHex": hex(&digest),
        "cases": cases,
        "maximalChunk": {
            "payload": payload_spec(0x5A, MAX_BULK_CHUNK_PAYLOAD_BYTES),
            "headerHex": hex(&maximal_encoded[..BULK_CHUNK_ENVELOPE_BYTES]),
            "encodedLength": maximal_encoded.len()
        }
    })
}

// --- tests ------------------------------------------------------------------

#[test]
fn remote_transport_frame_cross_language_conformance() {
    let fixture = frames_fixture();
    let cases = fixture["cases"].as_array().expect("cases");
    assert!(!cases.is_empty(), "fixture case count must be nonzero");
    assert_eq!(cases.len(), 6);

    for case in cases {
        // Every vector decodes back to the frame it describes.
        let header_hex = case["headerHex"].as_str().unwrap();
        assert_eq!(
            header_hex.len(),
            REMOTE_TRANSPORT_FRAME_HEADER_BYTES * 2,
            "{}: header must be exactly 72 bytes",
            case["name"]
        );
        // version | lane are the first two bytes.
        assert_eq!(&header_hex[..2], "01");
        let lane_id = case["laneId"].as_u64().unwrap() as u8;
        assert_eq!(
            &header_hex[2..4],
            &format!("{lane_id:02x}"),
            "{}: lane byte",
            case["name"]
        );
        // u64 fields are decimal strings in JSON, exact big-endian on the wire.
        assert!(case["streamId"].is_string());
        assert!(case["streamSeq"].is_string());
        let stream_id: u64 = case["streamId"].as_str().unwrap().parse().unwrap();
        assert_eq!(&header_hex[8..24], &hex(&stream_id.to_be_bytes()));
        let stream_seq: u64 = case["streamSeq"].as_str().unwrap().parse().unwrap();
        assert_eq!(&header_hex[24..40], &hex(&stream_seq.to_be_bytes()));
        // Frame ids are 22-character unpadded base64url.
        let id_text = case["frameId"].as_str().unwrap();
        assert_eq!(id_text.len(), 22);
        assert!(!id_text.contains('='));

        if let Some(encoded_hex) = case.get("encodedHex").and_then(|v| v.as_str()) {
            let bytes = (0..encoded_hex.len() / 2)
                .map(|i| u8::from_str_radix(&encoded_hex[i * 2..i * 2 + 2], 16).unwrap())
                .collect::<Vec<u8>>();
            let decoded = RemoteTransportFrameV1::decode(&bytes).expect("fixture frame decodes");
            assert_eq!(decoded.lane.as_str(), case["lane"].as_str().unwrap());
            assert_eq!(decoded.stream_id, stream_id);
            assert_eq!(decoded.stream_seq, stream_seq);
        }
    }
    sync_fixture("frames.json", &fixture);
}

#[test]
fn remote_transport_fragment_conformance() {
    let fixture = fragments_fixture();
    let cases = fixture["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 3);

    let maximal = cases
        .iter()
        .find(|case| case["name"] == "nine_fragment_maximal_bulk")
        .expect("maximal case");
    assert_eq!(maximal["serializedFrameLength"], json!(524_360));
    assert_eq!(maximal["fragmentCount"], json!(9));
    let fragments = maximal["fragments"].as_array().unwrap();
    assert_eq!(fragments.len(), 9);
    for (index, fragment) in fragments.iter().enumerate() {
        assert_eq!(fragment["index"], json!(index));
        assert_eq!(fragment["count"], json!(9));
        let is_final = index == 8;
        assert_eq!(fragment["flags"], json!(if is_final { 1 } else { 0 }));
        if !is_final {
            assert_eq!(fragment["payloadLength"], json!(65_471));
            assert_eq!(fragment["encodedLength"], json!(65_497));
        } else {
            assert_eq!(fragment["payloadLength"], json!(524_360 - 8 * 65_471));
        }
        assert_eq!(
            fragment["headerHex"].as_str().unwrap().len(),
            REMOTE_CARRIER_FRAGMENT_HEADER_BYTES * 2
        );
    }
    sync_fixture("fragments.json", &fixture);
}

#[test]
fn remote_transport_fixed_channel_contract_fixtures() {
    let fixture = channels_fixture();
    let channels = fixture["channels"].as_array().expect("channels");
    assert_eq!(channels.len(), 3);
    let ids: Vec<u64> = channels
        .iter()
        .map(|c| c["channelId"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, vec![0, 2, 4]);
    let labels: Vec<&str> = channels
        .iter()
        .map(|c| c["label"].as_str().unwrap())
        .collect();
    assert_eq!(
        labels,
        vec![
            "flycockpit.control.v1",
            "flycockpit.interactive.v1",
            "flycockpit.bulk.v1"
        ]
    );
    for channel in channels {
        assert_eq!(channel["negotiated"], json!(true));
        assert_eq!(channel["ordered"], json!(true));
        assert_eq!(channel["reliable"], json!(true));
        assert_eq!(channel["compressed"], json!(false));
    }
    sync_fixture("channels.json", &fixture);
}

#[test]
fn remote_transport_classification_is_exhaustive_fixtures() {
    let fixture = classification_fixture();
    let messages = &fixture["messages"];
    for kind in RemoteMessageKind::ALL {
        let rows = messages[kind.as_str()].as_array().expect("rows");
        assert!(!rows.is_empty(), "{} rows must be nonzero", kind.as_str());
        for row in rows {
            assert_ne!(row["tag"].as_str().unwrap(), UNKNOWN_MESSAGE_TAG);
            // Lane is derived from class and must agree in the fixture.
            let class = RemoteMessageClass::from_str_exact(row["class"].as_str().unwrap())
                .expect("known class");
            assert_eq!(row["lane"].as_str().unwrap(), class.lane().as_str());
        }
    }
    assert_eq!(
        fixture["counts"]["request"],
        json!(REQUEST_CLASSIFICATION.len())
    );
    assert_eq!(
        fixture["counts"]["response"],
        json!(RESPONSE_CLASSIFICATION.len())
    );
    assert_eq!(
        fixture["counts"]["event"],
        json!(EVENT_CLASSIFICATION.len())
    );
    assert!(!fixture["oversizedInventory"].as_array().unwrap().is_empty());
    sync_fixture("classification.json", &fixture);
}

#[test]
fn remote_bulk_window_and_integrity_fixtures() {
    let fixture = bulk_fixture();
    let cases = fixture["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 8);
    for case in cases {
        let hex_text = case["encodedHex"].as_str().unwrap();
        assert_eq!(hex_text.len() % 2, 0);
        assert_eq!(
            hex_text.len() / 2,
            case["encodedLength"].as_u64().unwrap() as usize
        );
        // The first byte is the kind discriminant, always 1..=4.
        let kind_byte = u8::from_str_radix(&hex_text[..2], 16).unwrap();
        assert!((1..=4).contains(&kind_byte), "{}", case["name"]);
    }
    // optionBits is visible in the fixture at a fixed offset for begins.
    let unknown = cases
        .iter()
        .find(|c| c["name"] == "begin_unknown_length")
        .unwrap();
    let known = cases
        .iter()
        .find(|c| c["name"] == "begin_known_prehashed")
        .unwrap();
    assert_eq!(
        unknown["encodedLength"],
        json!(BULK_BEGIN_BYTES_WITHOUT_OPTIONS)
    );
    assert_eq!(known["encodedLength"], json!(BULK_BEGIN_BYTES_WITH_OPTIONS));
    assert_eq!(&unknown["encodedHex"].as_str().unwrap()[34..36], "00");
    assert_eq!(&known["encodedHex"].as_str().unwrap()[34..36], "03");
    assert_eq!(
        fixture["maximalChunk"]["encodedLength"],
        json!(MAX_LOGICAL_PAYLOAD_BYTES)
    );
    sync_fixture("bulk.json", &fixture);
}

#[test]
fn remote_transport_constants_fixtures() {
    let fixture = constants_fixture();
    assert_eq!(fixture["ndjsonMaxFrameBytes"], json!(1_048_576));
    assert_eq!(fixture["frame"]["headerBytes"], json!(72));
    assert_eq!(fixture["fragment"]["headerBytes"], json!(26));
    assert_eq!(fixture["fragment"]["maxPayloadBytes"], json!(65_471));
    assert_eq!(fixture["fragment"]["laneFragmentTotalBytes"], json!(65_497));
    assert_eq!(fixture["fragment"]["maxFragmentCount"], json!(9));
    assert_eq!(
        fixture["laneSchedule"],
        json!([
            "control",
            "interactive",
            "control",
            "bulk",
            "interactive",
            "control",
            "interactive",
            "bulk"
        ])
    );
    sync_fixture("constants.json", &fixture);
}
