/**
 * Transport-neutral logical lanes — TypeScript mirror of
 * `crates/cockpit-proto/src/remote_transport/`.
 *
 * The two implementations are held together by the shared byte-exact fixtures
 * in `fixtures/remote-transport/`, which Rust generates and both sides verify.
 * Nothing here restates a constant that the fixtures already carry: the tests
 * read the numbers from the fixture files, so a change on either side that is
 * not mirrored fails.
 *
 * @see remote-transport-logical-lanes
 */
import {
  decodeProtocolIdBase64Url,
  encodeProtocolIdBase64Url,
  REMOTE_PROTOCOL_ID_BYTES,
} from "./remote-protocol-id";

// --- lanes ------------------------------------------------------------------

export const REMOTE_LANES = ["control", "interactive", "bulk"] as const;
export type RemoteLane = (typeof REMOTE_LANES)[number];

export const REMOTE_LANE_IDS: Readonly<Record<RemoteLane, number>> = {
  control: 0,
  interactive: 1,
  bulk: 2,
};

export const REMOTE_LANE_MAX_PAYLOAD_BYTES: Readonly<Record<RemoteLane, number>> = {
  control: 64 * 1024,
  interactive: 512 * 1024,
  bulk: 512 * 1024,
};

export function laneFromId(laneId: number): RemoteLane | undefined {
  return REMOTE_LANES.find((lane) => REMOTE_LANE_IDS[lane] === laneId);
}

// --- failure reasons --------------------------------------------------------

/** Closed reason codes, spelled exactly as the Rust `RemoteTransportReason`. */
export type RemoteTransportReason =
  | "unsupported_version"
  | "unknown_lane"
  | "unknown_flag_bit"
  | "header_too_short"
  | "trailing_bytes"
  | "payload_length_mismatch"
  | "payload_cap_exceeded"
  | "digest_mismatch"
  | "zero_stream_id"
  | "stream_parity_violation"
  | "control_stream_violation"
  | "sequence_gap"
  | "sequence_regression"
  | "sequence_wrap"
  | "stream_closed"
  | "stream_limit_exceeded"
  | "zero_fragment_count"
  | "fragment_count_exceeded"
  | "fragment_index_out_of_range"
  | "fragment_payload_cap_exceeded"
  | "fragment_length_mismatch"
  | "fragment_end_flag_misplaced"
  | "fragment_conflict"
  | "reassembly_frame_limit"
  | "reassembly_byte_limit"
  | "reassembly_timeout"
  | "bulk_unknown_kind"
  | "bulk_option_bits"
  | "bulk_length_mismatch"
  | "bulk_offset_gap"
  | "bulk_window_overshoot"
  | "bulk_transfer_limit"
  | "bulk_class_limit"
  | "bulk_digest_mismatch"
  | "bulk_unknown_transfer"
  | "bulk_transfer_conflict"
  | "bulk_late_chunk"
  | "bulk_already_complete"
  | "bulk_unknown_mime_class"
  | "bulk_unknown_abort_reason"
  | "bulk_chunk_index_gap"
  | "queue_frame_limit"
  | "queue_byte_limit"
  | "queue_aggregate_limit"
  | "control_queue_overflow"
  | "integer_out_of_range"
  | "unclassified_message"
  | "lane_not_permitted_for_class"
  | "client_selected_lane_rejected";

export type RemoteSizeBucket =
  | "le_1k"
  | "le_4k"
  | "le_16k"
  | "le_64k"
  | "le_256k"
  | "le_512k"
  | "gt_512k";

export function sizeBucketOf(bytes: number): RemoteSizeBucket {
  if (bytes <= 1024) return "le_1k";
  if (bytes <= 4 * 1024) return "le_4k";
  if (bytes <= 16 * 1024) return "le_16k";
  if (bytes <= 64 * 1024) return "le_64k";
  if (bytes <= 256 * 1024) return "le_256k";
  if (bytes <= 512 * 1024) return "le_512k";
  return "gt_512k";
}

/** Payload-free transport failure; renders exactly like the Rust `Display`. */
export class RemoteTransportError extends Error {
  readonly reason: RemoteTransportReason;
  readonly lane: RemoteLane | undefined;
  readonly sizeBucket: RemoteSizeBucket | undefined;

  constructor(reason: RemoteTransportReason, lane?: RemoteLane, sizeBytes?: number) {
    const bucket = sizeBytes === undefined ? undefined : sizeBucketOf(sizeBytes);
    let text: string = reason;
    if (lane !== undefined) text += ` lane=${lane}`;
    if (bucket !== undefined) text += ` size=${bucket}`;
    super(text);
    this.name = "RemoteTransportError";
    this.reason = reason;
    this.lane = lane;
    this.sizeBucket = bucket;
  }
}

function fail(reason: RemoteTransportReason, lane?: RemoteLane, sizeBytes?: number): never {
  throw new RemoteTransportError(reason, lane, sizeBytes);
}

// --- byte helpers -----------------------------------------------------------

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex length must be even");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error("invalid hex");
    out[i] = byte;
  }
  return out;
}

/** SHA-256 via WebCrypto — available in Node, browsers, and React Native. */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
  return new Uint8Array(digest);
}

function writeU16Be(target: Uint8Array, offset: number, value: number): void {
  target[offset] = (value >>> 8) & 0xff;
  target[offset + 1] = value & 0xff;
}

function readU16Be(source: Uint8Array, offset: number): number {
  return ((source[offset]! << 8) | source[offset + 1]!) >>> 0;
}

function writeU32Be(target: Uint8Array, offset: number, value: number): void {
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

function readU32Be(source: Uint8Array, offset: number): number {
  return (
    ((source[offset]! << 24) >>> 0) +
    (source[offset + 1]! << 16) +
    (source[offset + 2]! << 8) +
    source[offset + 3]!
  );
}

function writeU64Be(target: Uint8Array, offset: number, value: bigint): void {
  let remaining = value;
  for (let i = 7; i >= 0; i--) {
    target[offset + i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
}

function readU64Be(source: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 0; i < 8; i++) {
    value = (value << 8n) | BigInt(source[offset + i]!);
  }
  return value;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// --- RemoteTransportFrameV1 -------------------------------------------------

export const REMOTE_TRANSPORT_FRAME_VERSION = 1;
export const REMOTE_TRANSPORT_FRAME_HEADER_BYTES = 72;
export const MAX_LOGICAL_PAYLOAD_BYTES = 512 * 1024;
export const MAX_SERIALIZED_FRAME_BYTES =
  REMOTE_TRANSPORT_FRAME_HEADER_BYTES + MAX_LOGICAL_PAYLOAD_BYTES;

export const FRAME_FLAG_END_STREAM = 0x0001;
export const FRAME_FLAG_RESET_STREAM = 0x0002;
export const FRAME_FLAGS_DEFINED = FRAME_FLAG_END_STREAM | FRAME_FLAG_RESET_STREAM;

export const CONTROL_STREAM_ID = 0n;

export interface RemoteTransportFrameV1 {
  readonly lane: RemoteLane;
  readonly flags: number;
  readonly streamId: bigint;
  readonly streamSeq: bigint;
  /** Raw 16 bytes; the JSON spelling is 22-char base64url. */
  readonly frameId: Uint8Array;
  readonly payload: Uint8Array;
}

/** Which peer created a stream. */
export type RemoteStreamOrigin = "client" | "daemon";

export function streamOriginOf(streamId: bigint): RemoteStreamOrigin | undefined {
  if (streamId === CONTROL_STREAM_ID) return undefined;
  return streamId % 2n === 0n ? "client" : "daemon";
}

export function validateStreamId(
  streamId: bigint,
  origin: RemoteStreamOrigin,
  lane: RemoteLane,
): void {
  if (streamId === CONTROL_STREAM_ID) {
    // Stream 0 is control-only.
    if (lane !== "control") fail("zero_stream_id", lane);
    return;
  }
  if (streamOriginOf(streamId) !== origin) fail("stream_parity_violation", lane);
}

export async function encodeRemoteTransportFrame(
  frame: RemoteTransportFrameV1,
): Promise<Uint8Array> {
  if (frame.payload.length > REMOTE_LANE_MAX_PAYLOAD_BYTES[frame.lane]) {
    fail("payload_cap_exceeded", frame.lane, frame.payload.length);
  }
  requireOpaqueId(frame.frameId, "payload_length_mismatch", frame.lane);
  requireU64(frame.streamId, frame.lane);
  requireU64(frame.streamSeq, frame.lane);
  if ((frame.flags & ~FRAME_FLAGS_DEFINED) !== 0) fail("unknown_flag_bit", frame.lane);

  const digest = await sha256(frame.payload);
  const out = new Uint8Array(REMOTE_TRANSPORT_FRAME_HEADER_BYTES + frame.payload.length);
  out[0] = REMOTE_TRANSPORT_FRAME_VERSION;
  out[1] = REMOTE_LANE_IDS[frame.lane];
  writeU16Be(out, 2, frame.flags);
  writeU64Be(out, 4, frame.streamId);
  writeU64Be(out, 12, frame.streamSeq);
  out.set(frame.frameId, 20);
  writeU32Be(out, 36, frame.payload.length);
  out.set(digest, 40);
  out.set(frame.payload, REMOTE_TRANSPORT_FRAME_HEADER_BYTES);
  return out;
}

export async function decodeRemoteTransportFrame(
  bytes: Uint8Array,
): Promise<RemoteTransportFrameV1> {
  if (bytes.length < REMOTE_TRANSPORT_FRAME_HEADER_BYTES) fail("header_too_short");
  if (bytes[0] !== REMOTE_TRANSPORT_FRAME_VERSION) fail("unsupported_version");
  const lane = laneFromId(bytes[1]!);
  if (lane === undefined) fail("unknown_lane");
  const flags = readU16Be(bytes, 2);
  if ((flags & ~FRAME_FLAGS_DEFINED) !== 0) fail("unknown_flag_bit", lane);
  const streamId = readU64Be(bytes, 4);
  const streamSeq = readU64Be(bytes, 12);
  const frameId = bytes.slice(20, 36);
  requireOpaqueId(frameId, "payload_length_mismatch", lane);
  const payloadLength = readU32Be(bytes, 36);

  // Bound the declared length before it can size anything.
  if (payloadLength > REMOTE_LANE_MAX_PAYLOAD_BYTES[lane]) {
    fail("payload_cap_exceeded", lane, payloadLength);
  }
  const actual = bytes.length - REMOTE_TRANSPORT_FRAME_HEADER_BYTES;
  if (actual > payloadLength) fail("trailing_bytes", lane);
  if (actual < payloadLength) fail("payload_length_mismatch", lane);

  const declaredDigest = bytes.slice(40, REMOTE_TRANSPORT_FRAME_HEADER_BYTES);
  const payload = bytes.slice(REMOTE_TRANSPORT_FRAME_HEADER_BYTES);
  if (!equalBytes(await sha256(payload), declaredDigest)) fail("digest_mismatch", lane);

  return { lane, flags, streamId, streamSeq, frameId, payload };
}

/** Most streams one peer may hold open at once. Mirrors Rust. */
export const MAX_ACTIVE_STREAMS_PER_PEER = 256;

/**
 * Per-stream sequence validation, stream retirement, and the active-stream
 * budget. Mirrors Rust `RemoteStreamSequences`.
 *
 * A stream id is retired once its stream closes and may never be reused, which
 * is what stops a terminal frame being replayed.
 *
 * Retirement is a **contiguous closed prefix**, not a high-water mark. A stream
 * only enters the open set when its first frame completes, and fragmentation
 * reorders completion relative to receipt: a large first frame on stream 4 may
 * still be reassembling when stream 6's small terminal frame completes and
 * closes. Retiring "everything at or below the highest closed id" would drop
 * stream 4 — a live stream. So an id is retired only when explicitly recorded
 * closed, or when it lies below a contiguous run of closed ordinals reaching
 * back to the lane's first legal ordinal.
 *
 * The closed set is bounded by an outstanding-id window rather than allowed to
 * grow, so this is not an unbounded tombstone set: once the prefix fills, the
 * set collapses back to empty.
 */
export const MAX_OUTSTANDING_STREAM_IDS = 1024;

interface LaneStreamState {
  retireCursor: bigint;
  closed: Set<bigint>;
}

export class RemoteStreamSequences {
  private readonly next = new Map<string, bigint>();
  private readonly lanes = new Map<RemoteLane, LaneStreamState>();

  constructor(
    private readonly origin: RemoteStreamOrigin = "client",
    private readonly maxActive: number = MAX_ACTIVE_STREAMS_PER_PEER,
    private readonly maxOutstanding: bigint = BigInt(MAX_OUTSTANDING_STREAM_IDS),
  ) {}

  private static key(lane: RemoteLane, streamId: bigint): string {
    return `${lane}:${streamId}`;
  }

  /** Position of a stream id within its lane's allocation sequence. */
  private ordinal(streamId: bigint): bigint {
    if (streamId === CONTROL_STREAM_ID) return 0n;
    return this.origin === "client" ? streamId / 2n : (streamId + 1n) / 2n;
  }

  private laneState(lane: RemoteLane): LaneStreamState {
    let state = this.lanes.get(lane);
    if (state === undefined) {
      // Stream 0 exists only on control, so every other lane starts one higher.
      state = { retireCursor: lane === "control" ? 0n : 1n, closed: new Set() };
      this.lanes.set(lane, state);
    }
    return state;
  }

  accept(lane: RemoteLane, streamId: bigint, streamSeq: bigint): void {
    const key = RemoteStreamSequences.key(lane, streamId);
    const expected = this.next.get(key);
    if (expected !== undefined) {
      if (streamSeq < expected) fail("sequence_regression", lane);
      if (streamSeq > expected) fail("sequence_gap", lane);
      const advanced = streamSeq + 1n;
      if (advanced > U64_MAX_VALUE) fail("sequence_wrap", lane);
      this.next.set(key, advanced);
      return;
    }
    const ordinal = this.ordinal(streamId);
    const state = this.laneState(lane);
    if (ordinal < state.retireCursor || state.closed.has(ordinal)) {
      fail("stream_closed", lane);
    }
    if (ordinal - state.retireCursor >= this.maxOutstanding) {
      fail("stream_limit_exceeded", lane);
    }
    if (streamSeq !== 0n) fail("sequence_gap", lane);
    if (this.next.size >= this.maxActive) fail("stream_limit_exceeded", lane);
    this.next.set(key, 1n);
  }

  /** Retire a stream after END_STREAM / RESET_STREAM. */
  close(lane: RemoteLane, streamId: bigint): void {
    this.next.delete(RemoteStreamSequences.key(lane, streamId));
    const ordinal = this.ordinal(streamId);
    const state = this.laneState(lane);
    if (ordinal < state.retireCursor) return;
    state.closed.add(ordinal);
    while (state.closed.delete(state.retireCursor)) {
      state.retireCursor += 1n;
    }
  }

  get trackedStreams(): number {
    return this.next.size;
  }

  /** Closed ordinals still held out of the prefix, across every lane. */
  get pendingClosedOrdinals(): number {
    let total = 0;
    for (const state of this.lanes.values()) total += state.closed.size;
    return total;
  }
}

// --- RemoteCarrierFragmentV1 ------------------------------------------------

export const REMOTE_CARRIER_FRAGMENT_VERSION = 1;
export const REMOTE_CARRIER_FRAGMENT_HEADER_BYTES = 26;

export const NOISE_RECORD_MAX_CIPHERTEXT_BYTES = 65_535;
export const NOISE_AEAD_TAG_BYTES = 16;
export const NOISE_MAX_PLAINTEXT_BYTES = NOISE_RECORD_MAX_CIPHERTEXT_BYTES - NOISE_AEAD_TAG_BYTES;
export const NOISE_RECORD_HEADER_BYTES = 14;
export const NOISE_RECORD_PAYLOAD_BYTES = NOISE_MAX_PLAINTEXT_BYTES - NOISE_RECORD_HEADER_BYTES;
export const PEER_SEEN_THROUGH_WATERMARK_BYTES = 8;
export const LANE_FRAGMENT_TOTAL_BYTES =
  NOISE_RECORD_PAYLOAD_BYTES - PEER_SEEN_THROUGH_WATERMARK_BYTES;
export const REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES =
  LANE_FRAGMENT_TOTAL_BYTES - REMOTE_CARRIER_FRAGMENT_HEADER_BYTES;

export const MAX_FRAGMENT_COUNT = 9;
export const FRAGMENT_FLAG_END = 0x0001;
export const FRAGMENT_FLAGS_DEFINED = FRAGMENT_FLAG_END;

export const MAX_INCOMPLETE_FRAMES_PER_PEER = 16;
export const MAX_REASSEMBLY_BYTES_PER_PEER = 8 * 1024 * 1024;
export const REASSEMBLY_DEADLINE_MS = 5_000;

/**
 * Completed frame ids remembered per peer, so a replayed or reused id is caught
 * rather than treated as a brand-new frame.
 *
 * Frame ids are random 128-bit values, so the contiguous-closed-prefix rule
 * that retires *stream* ids does not apply: random ids have no ordering, so
 * there is no prefix to collapse and a retired-id set would grow without bound.
 * A frame id only has to stay unique for the retention window, so a bounded,
 * expiry-aligned memory is the right shape instead.
 */
export const MAX_COMPLETED_FRAME_MEMORY = 64;

export interface RemoteCarrierFragmentV1 {
  readonly lane: RemoteLane;
  readonly flags: number;
  readonly frameId: Uint8Array;
  readonly fragmentIndex: number;
  readonly fragmentCount: number;
  readonly bytes: Uint8Array;
}

/**
 * Route a raw 16-byte identifier through the landed opaque-ID codec, so
 * TypeScript rejects exactly what Rust's `tag_protocol_id_bytes` rejects:
 * a wrong length or an all-zero value. `reason` mirrors the reason Rust maps
 * that rejection to in each decoder.
 */
function requireOpaqueId(id: Uint8Array, reason: RemoteTransportReason, lane?: RemoteLane): void {
  if (id.length !== REMOTE_PROTOCOL_ID_BYTES) fail(reason, lane);
  try {
    encodeProtocolIdBase64Url(id);
  } catch {
    fail(reason, lane);
  }
}

/** A SHA-256 must be exactly 32 bytes. */
function requireDigestLength(digest: Uint8Array): void {
  if (digest.length !== 32) fail("bulk_digest_mismatch", "bulk");
}

/** Largest value a `u64` wire field can carry. */
export const U64_MAX_VALUE = 18446744073709551615n;
/** Largest value a `u32` wire field can carry. */
export const U32_MAX_VALUE = 4294967295;

/**
 * Range-check a value destined for a fixed-width unsigned wire field.
 *
 * Rust gets this from its type system; TypeScript's `bigint`/`number` do not,
 * and silently truncating would make TS fail to round-trip its own input.
 */
function requireU64(value: bigint, lane?: RemoteLane): void {
  if (value < 0n || value > U64_MAX_VALUE) fail("integer_out_of_range", lane);
}

function requireU32(value: number, lane?: RemoteLane): void {
  if (!Number.isInteger(value) || value < 0 || value > U32_MAX_VALUE) {
    fail("integer_out_of_range", lane);
  }
}

/**
 * Mirror of Rust `RemoteBulkBegin::validate`.
 *
 * `optionBits` must agree with the present fields, `maxTotalLength` must be
 * exactly the class maximum, and a declared total must fit inside it.
 */
function validateBulkBegin(begin: RemoteBulkBegin): void {
  const bothPresent = begin.totalLength !== undefined && begin.expectedSha256 !== undefined;
  const bothAbsent = begin.totalLength === undefined && begin.expectedSha256 === undefined;
  if (!bothPresent && !bothAbsent) fail("bulk_option_bits", "bulk");
  if (begin.maxTotalLength !== REMOTE_BULK_MIME_CLASS_MAX_TOTAL_LENGTH[begin.mimeClass]) {
    fail("bulk_class_limit", "bulk");
  }
  if (begin.totalLength !== undefined && begin.totalLength > begin.maxTotalLength) {
    fail("bulk_transfer_limit", "bulk");
  }
}

/** Largest value a `u16` wire field can carry. */
export const U16_MAX_VALUE = 65535;

function requireU16(value: number, lane?: RemoteLane): void {
  if (!Number.isInteger(value) || value < 0 || value > U16_MAX_VALUE) {
    fail("integer_out_of_range", lane);
  }
}

function validateFragmentShape(fragment: RemoteCarrierFragmentV1): void {
  // Rust gets these bounds from `u16`. Without them TypeScript would encode a
  // negative index as 0xffff — an input Rust cannot construct and both
  // decoders reject.
  requireU16(fragment.fragmentIndex, fragment.lane);
  requireU16(fragment.fragmentCount, fragment.lane);
  requireU16(fragment.flags, fragment.lane);
  // Only END exists. Rust cannot construct any other RemoteFragmentFlags, so
  // TypeScript must not encode one either — the decoders would reject it.
  if ((fragment.flags & ~FRAGMENT_FLAGS_DEFINED) !== 0) {
    fail("unknown_flag_bit", fragment.lane);
  }
  if (fragment.bytes.length > REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES) {
    fail("fragment_payload_cap_exceeded", fragment.lane, fragment.bytes.length);
  }
  if (fragment.fragmentCount === 0) fail("zero_fragment_count", fragment.lane);
  if (fragment.fragmentCount > MAX_FRAGMENT_COUNT) {
    fail("fragment_count_exceeded", fragment.lane);
  }
  if (fragment.fragmentIndex >= fragment.fragmentCount) {
    fail("fragment_index_out_of_range", fragment.lane);
  }
  const isFinal = fragment.fragmentIndex + 1 === fragment.fragmentCount;
  if (((fragment.flags & FRAGMENT_FLAG_END) !== 0) !== isFinal) {
    fail("fragment_end_flag_misplaced", fragment.lane);
  }
}

export function encodeRemoteCarrierFragment(fragment: RemoteCarrierFragmentV1): Uint8Array {
  validateFragmentShape(fragment);
  requireOpaqueId(fragment.frameId, "fragment_conflict", fragment.lane);
  const out = new Uint8Array(REMOTE_CARRIER_FRAGMENT_HEADER_BYTES + fragment.bytes.length);
  out[0] = REMOTE_CARRIER_FRAGMENT_VERSION;
  out[1] = REMOTE_LANE_IDS[fragment.lane];
  writeU16Be(out, 2, fragment.flags);
  out.set(fragment.frameId, 4);
  writeU16Be(out, 20, fragment.fragmentIndex);
  writeU16Be(out, 22, fragment.fragmentCount);
  writeU16Be(out, 24, fragment.bytes.length);
  out.set(fragment.bytes, REMOTE_CARRIER_FRAGMENT_HEADER_BYTES);
  return out;
}

export function decodeRemoteCarrierFragment(bytes: Uint8Array): RemoteCarrierFragmentV1 {
  if (bytes.length < REMOTE_CARRIER_FRAGMENT_HEADER_BYTES) fail("header_too_short");
  if (bytes[0] !== REMOTE_CARRIER_FRAGMENT_VERSION) fail("unsupported_version");
  const lane = laneFromId(bytes[1]!);
  if (lane === undefined) fail("unknown_lane");
  const flags = readU16Be(bytes, 2);
  if ((flags & ~FRAGMENT_FLAGS_DEFINED) !== 0) fail("unknown_flag_bit", lane);
  const frameId = bytes.slice(4, 20);
  requireOpaqueId(frameId, "fragment_conflict", lane);
  const fragmentIndex = readU16Be(bytes, 20);
  const fragmentCount = readU16Be(bytes, 22);
  const declaredLength = readU16Be(bytes, 24);

  if (declaredLength > REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES) {
    fail("fragment_payload_cap_exceeded", lane, declaredLength);
  }
  const actual = bytes.length - REMOTE_CARRIER_FRAGMENT_HEADER_BYTES;
  if (actual > declaredLength) fail("trailing_bytes", lane);
  if (actual < declaredLength) fail("fragment_length_mismatch", lane);

  const fragment: RemoteCarrierFragmentV1 = {
    lane,
    flags,
    frameId,
    fragmentIndex,
    fragmentCount,
    bytes: bytes.slice(REMOTE_CARRIER_FRAGMENT_HEADER_BYTES),
  };
  validateFragmentShape(fragment);
  return fragment;
}

/**
 * Canonical split: every fragment but the last carries exactly
 * `REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES`. This is what makes WebRTC and
 * fallback fragment bytes identical.
 */
export function fragmentFrame(
  lane: RemoteLane,
  frameId: Uint8Array,
  serializedFrame: Uint8Array,
): RemoteCarrierFragmentV1[] {
  if (serializedFrame.length < REMOTE_TRANSPORT_FRAME_HEADER_BYTES) fail("header_too_short", lane);
  if (serializedFrame.length > MAX_SERIALIZED_FRAME_BYTES) {
    fail("payload_cap_exceeded", lane, serializedFrame.length);
  }
  const count = Math.max(
    1,
    Math.ceil(serializedFrame.length / REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES),
  );
  if (count > MAX_FRAGMENT_COUNT) fail("fragment_count_exceeded", lane);
  const fragments: RemoteCarrierFragmentV1[] = [];
  for (let index = 0; index < count; index++) {
    const start = index * REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES;
    const end = Math.min(start + REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES, serializedFrame.length);
    const isFinal = index + 1 === count;
    fragments.push({
      lane,
      flags: isFinal ? FRAGMENT_FLAG_END : 0,
      frameId,
      fragmentIndex: index,
      fragmentCount: count,
      bytes: serializedFrame.slice(start, end),
    });
  }
  return fragments;
}

interface CompletedFrame {
  atMs: number;
  /** The exact 72-byte header, so a byte-identical retry is distinguishable
   * from a different frame wearing the same id — including one that differs
   * only by stream sequence, which the sequence check alone would accept. */
  header: Uint8Array;
}

interface PartialFrame {
  lane: RemoteLane;
  fragmentCount: number;
  slots: (Uint8Array | undefined)[];
  bufferedBytes: number;
  firstSeenMs: number;
}

/** Bounded per-peer reassembly with an injected clock. */
export class RemoteFragmentReassembler {
  private readonly partials = new Map<string, PartialFrame>();
  /** Frame ids that completed inside the retention window. */
  private readonly completed = new Map<string, CompletedFrame>();
  private readonly sequences: RemoteStreamSequences;
  private buffered = 0;

  private readonly origin: RemoteStreamOrigin;

  constructor(
    peerOrigin: RemoteStreamOrigin = "client",
    private readonly maxFrames = MAX_INCOMPLETE_FRAMES_PER_PEER,
    private readonly maxBytes = MAX_REASSEMBLY_BYTES_PER_PEER,
    private readonly deadlineMs = REASSEMBLY_DEADLINE_MS,
  ) {
    this.origin = peerOrigin;
    this.sequences = new RemoteStreamSequences(peerOrigin);
  }

  /** Streams currently open on this peer. */
  get trackedStreams(): number {
    return this.sequences.trackedStreams;
  }

  get incompleteFrames(): number {
    return this.partials.size;
  }

  get bufferedBytes(): number {
    return this.buffered;
  }

  expire(nowMs: number): number {
    let dropped = 0;
    for (const [key, partial] of [...this.partials]) {
      if (nowMs - partial.firstSeenMs >= this.deadlineMs) {
        this.buffered -= partial.bufferedBytes;
        this.partials.delete(key);
        dropped++;
      }
    }
    // The completion memory drains on the same deadline, so the retention
    // window and the reassembly window are the same window.
    for (const [key, done] of [...this.completed]) {
      if (nowMs - done.atMs >= this.deadlineMs) this.completed.delete(key);
    }
    return dropped;
  }

  /** Frame ids remembered from completed frames. */
  get rememberedFrames(): number {
    return this.completed.size;
  }

  /**
   * Accept one fragment, yielding a **dispatchable** frame once the last one
   * lands.
   *
   * Mirrors Rust `RemoteFragmentReassembler::accept`: the reassembled bytes are
   * not handed back raw. The complete 72-byte frame and its SHA-256 digest are
   * validated, then stream ownership and per-stream sequence are checked,
   * before anything is returned. Yielding unvalidated bytes here would make
   * the receive gate a caller obligation, and a corrupted payload with
   * well-formed fragments would reach the application as complete data.
   */
  async accept(
    fragment: RemoteCarrierFragmentV1,
    nowMs: number,
  ): Promise<RemoteTransportFrameV1 | undefined> {
    const serialized = this.assemble(fragment, nowMs);
    if (serialized === undefined) return undefined;
    // Validates the fixed header, the length, and the payload digest.
    const frame = await decodeRemoteTransportFrame(serialized);
    if (frame.lane !== fragment.lane || !equalBytes(frame.frameId, fragment.frameId)) {
      fail("fragment_conflict", fragment.lane);
    }
    const key = bytesToHex(fragment.frameId);
    const header = serialized.slice(0, REMOTE_TRANSPORT_FRAME_HEADER_BYTES);
    const done = this.completed.get(key);
    if (done !== undefined) {
      // A frame id must stay unique for the retention window. A byte-identical
      // retry is idempotent and must not dispatch twice; anything else wearing
      // the same id is conflicting reuse. The sequence check cannot catch the
      // latter: reusing an id on the next sequence number satisfies it.
      if (equalBytes(done.header, header)) return undefined;
      fail("fragment_conflict", fragment.lane);
    }
    validateStreamId(frame.streamId, this.peerOriginOf(), frame.lane);
    this.sequences.accept(frame.lane, frame.streamId, frame.streamSeq);
    if ((frame.flags & (FRAME_FLAG_END_STREAM | FRAME_FLAG_RESET_STREAM)) !== 0) {
      // Retires the id: it leaves the active budget but can never be reused,
      // so the terminal frame itself is not replayable.
      this.sequences.close(frame.lane, frame.streamId);
    }
    // Remembered only once every rule has passed, so a rejected frame may still
    // be retried. The memory is capped; the oldest entry makes way when full.
    if (this.completed.size >= MAX_COMPLETED_FRAME_MEMORY) {
      let oldestKey: string | undefined;
      let oldestAt = Number.POSITIVE_INFINITY;
      for (const [candidate, entry] of this.completed) {
        if (entry.atMs < oldestAt) {
          oldestAt = entry.atMs;
          oldestKey = candidate;
        }
      }
      if (oldestKey !== undefined) this.completed.delete(oldestKey);
    }
    this.completed.set(key, { atMs: nowMs, header });
    return frame;
  }

  private peerOriginOf(): RemoteStreamOrigin {
    return this.origin;
  }

  /** Raw fragment assembly. Returns serialized frame bytes, unvalidated. */
  private assemble(fragment: RemoteCarrierFragmentV1, nowMs: number): Uint8Array | undefined {
    // A caller-built fragment has not been through `decode`, so validate it
    // here too: an out-of-range index would otherwise punch a hole in `slots`
    // and complete the frame early.
    validateFragmentShape(fragment);
    requireOpaqueId(fragment.frameId, "fragment_conflict", fragment.lane);
    this.expire(nowMs);
    const key = bytesToHex(fragment.frameId);
    let partial = this.partials.get(key);
    const isNew = partial === undefined;
    if (partial === undefined) {
      if (this.partials.size >= this.maxFrames) fail("reassembly_frame_limit", fragment.lane);
      partial = {
        lane: fragment.lane,
        fragmentCount: fragment.fragmentCount,
        slots: new Array<Uint8Array | undefined>(fragment.fragmentCount).fill(undefined),
        bufferedBytes: 0,
        firstSeenMs: nowMs,
      };
      this.partials.set(key, partial);
    }
    // A rejected first fragment must not leave a slot consumed until the
    // reassembly deadline.
    const reject = (reason: RemoteTransportReason, sizeBytes?: number): never => {
      if (isNew) this.partials.delete(key);
      return fail(reason, fragment.lane, sizeBytes);
    };
    if (partial.lane !== fragment.lane || partial.fragmentCount !== fragment.fragmentCount) {
      reject("fragment_conflict");
    }
    const existing = partial.slots[fragment.fragmentIndex];
    if (existing !== undefined) {
      // Exact duplicates are idempotent; conflicting ones close the stream.
      if (equalBytes(existing, fragment.bytes)) return undefined;
      reject("fragment_conflict");
    }
    if (this.buffered + fragment.bytes.length > this.maxBytes) {
      reject("reassembly_byte_limit", fragment.bytes.length);
    }
    if (partial.bufferedBytes + fragment.bytes.length > MAX_SERIALIZED_FRAME_BYTES) {
      reject("reassembly_byte_limit", fragment.bytes.length);
    }
    partial.slots[fragment.fragmentIndex] = fragment.bytes;
    partial.bufferedBytes += fragment.bytes.length;
    this.buffered += fragment.bytes.length;

    if (partial.slots.some((slot) => slot === undefined)) return undefined;

    this.partials.delete(key);
    this.buffered -= partial.bufferedBytes;
    const out = new Uint8Array(partial.bufferedBytes);
    let offset = 0;
    for (const slot of partial.slots) {
      out.set(slot!, offset);
      offset += slot!.length;
    }
    return out;
  }
}

// --- bulk transfer payloads -------------------------------------------------

export const BULK_KIND_BEGIN = 1;
export const BULK_KIND_CHUNK = 2;
export const BULK_KIND_COMPLETE = 3;
export const BULK_KIND_ABORT = 4;

export const BULK_OPTION_BITS_UNKNOWN = 0x00;
export const BULK_OPTION_BITS_KNOWN = 0x03;

export const BULK_BEGIN_BYTES_WITHOUT_OPTIONS = 27;
export const BULK_BEGIN_BYTES_WITH_OPTIONS = 67;
export const BULK_CHUNK_ENVELOPE_BYTES = 33;
export const BULK_COMPLETE_BYTES = 57;
export const BULK_ABORT_BYTES = 18;
export const MAX_BULK_CHUNK_PAYLOAD_BYTES =
  REMOTE_LANE_MAX_PAYLOAD_BYTES.bulk - BULK_CHUNK_ENVELOPE_BYTES;

export const MAX_RECEIVER_WINDOW_BYTES = 4n * 1024n * 1024n;
export const MAX_TRANSFER_BYTES = 512n * 1024n * 1024n;

export const REMOTE_BULK_MIME_CLASSES = [
  "image",
  "image_set",
  "archive",
  "export",
  "opaque",
] as const;
export type RemoteBulkMimeClass = (typeof REMOTE_BULK_MIME_CLASSES)[number];

export const REMOTE_BULK_MIME_CLASS_CODES: Readonly<Record<RemoteBulkMimeClass, number>> = {
  image: 1,
  image_set: 2,
  archive: 3,
  export: 4,
  opaque: 5,
};

/**
 * Authoritative per-class ceiling, mirroring Rust
 * `RemoteBulkMimeClass::max_total_length`. The landed 4 MiB single-image and
 * 8 MiB total-image limits stay authoritative; everything else is the 512 MiB
 * global transfer cap.
 */
export const REMOTE_BULK_MIME_CLASS_MAX_TOTAL_LENGTH: Readonly<
  Record<RemoteBulkMimeClass, bigint>
> = {
  image: 4n * 1024n * 1024n,
  image_set: 8n * 1024n * 1024n,
  archive: MAX_TRANSFER_BYTES,
  export: MAX_TRANSFER_BYTES,
  opaque: MAX_TRANSFER_BYTES,
};

export const REMOTE_BULK_ABORT_REASONS = [
  "cancelled",
  "limit_exceeded",
  "integrity_failure",
  "transport_closed",
  "timeout",
] as const;
export type RemoteBulkAbortReason = (typeof REMOTE_BULK_ABORT_REASONS)[number];

export const REMOTE_BULK_ABORT_REASON_CODES: Readonly<Record<RemoteBulkAbortReason, number>> = {
  cancelled: 1,
  limit_exceeded: 2,
  integrity_failure: 3,
  transport_closed: 4,
  timeout: 5,
};

export interface RemoteBulkBegin {
  readonly kind: "begin";
  readonly transferId: Uint8Array;
  readonly totalLength: bigint | undefined;
  readonly expectedSha256: Uint8Array | undefined;
  readonly mimeClass: RemoteBulkMimeClass;
  readonly maxTotalLength: bigint;
}

export interface RemoteBulkChunk {
  readonly kind: "chunk";
  readonly transferId: Uint8Array;
  readonly chunkIndex: number;
  readonly offset: bigint;
  readonly bytes: Uint8Array;
}

export interface RemoteBulkComplete {
  readonly kind: "complete";
  readonly transferId: Uint8Array;
  readonly finalLength: bigint;
  readonly sha256: Uint8Array;
}

export interface RemoteBulkAbort {
  readonly kind: "abort";
  readonly transferId: Uint8Array;
  readonly reason: RemoteBulkAbortReason;
}

export type RemoteBulkMessage =
  | RemoteBulkBegin
  | RemoteBulkChunk
  | RemoteBulkComplete
  | RemoteBulkAbort;

function mimeClassFromCode(code: number): RemoteBulkMimeClass | undefined {
  return REMOTE_BULK_MIME_CLASSES.find((name) => REMOTE_BULK_MIME_CLASS_CODES[name] === code);
}

function abortReasonFromCode(code: number): RemoteBulkAbortReason | undefined {
  return REMOTE_BULK_ABORT_REASONS.find((name) => REMOTE_BULK_ABORT_REASON_CODES[name] === code);
}

export function encodeRemoteBulkMessage(message: RemoteBulkMessage): Uint8Array {
  switch (message.kind) {
    case "begin": {
      const hasOptions = message.totalLength !== undefined && message.expectedSha256 !== undefined;
      const halfPopulated =
        (message.totalLength === undefined) !== (message.expectedSha256 === undefined);
      if (halfPopulated) fail("bulk_option_bits", "bulk");
      requireOpaqueId(message.transferId, "bulk_unknown_transfer", "bulk");
      if (message.expectedSha256 !== undefined) requireDigestLength(message.expectedSha256);
      validateBulkBegin(message);
      if (message.totalLength !== undefined) requireU64(message.totalLength, "bulk");
      requireU64(message.maxTotalLength, "bulk");
      const size = hasOptions ? BULK_BEGIN_BYTES_WITH_OPTIONS : BULK_BEGIN_BYTES_WITHOUT_OPTIONS;
      const out = new Uint8Array(size);
      out[0] = BULK_KIND_BEGIN;
      out.set(message.transferId, 1);
      out[17] = hasOptions ? BULK_OPTION_BITS_KNOWN : BULK_OPTION_BITS_UNKNOWN;
      let cursor = 18;
      if (hasOptions) {
        writeU64Be(out, cursor, message.totalLength!);
        cursor += 8;
        out.set(message.expectedSha256!, cursor);
        cursor += 32;
      }
      out[cursor] = REMOTE_BULK_MIME_CLASS_CODES[message.mimeClass];
      writeU64Be(out, cursor + 1, message.maxTotalLength);
      return out;
    }
    case "chunk": {
      requireOpaqueId(message.transferId, "bulk_unknown_transfer", "bulk");
      requireU32(message.chunkIndex, "bulk");
      requireU64(message.offset, "bulk");
      if (message.bytes.length > MAX_BULK_CHUNK_PAYLOAD_BYTES) {
        fail("payload_cap_exceeded", "bulk", message.bytes.length);
      }
      const out = new Uint8Array(BULK_CHUNK_ENVELOPE_BYTES + message.bytes.length);
      out[0] = BULK_KIND_CHUNK;
      out.set(message.transferId, 1);
      writeU32Be(out, 17, message.chunkIndex);
      writeU64Be(out, 21, message.offset);
      writeU32Be(out, 29, message.bytes.length);
      out.set(message.bytes, BULK_CHUNK_ENVELOPE_BYTES);
      return out;
    }
    case "complete": {
      requireOpaqueId(message.transferId, "bulk_unknown_transfer", "bulk");
      requireDigestLength(message.sha256);
      requireU64(message.finalLength, "bulk");
      const out = new Uint8Array(BULK_COMPLETE_BYTES);
      out[0] = BULK_KIND_COMPLETE;
      out.set(message.transferId, 1);
      writeU64Be(out, 17, message.finalLength);
      out.set(message.sha256, 25);
      return out;
    }
    case "abort": {
      requireOpaqueId(message.transferId, "bulk_unknown_transfer", "bulk");
      const out = new Uint8Array(BULK_ABORT_BYTES);
      out[0] = BULK_KIND_ABORT;
      out.set(message.transferId, 1);
      out[17] = REMOTE_BULK_ABORT_REASON_CODES[message.reason];
      return out;
    }
  }
}

export function decodeRemoteBulkMessage(bytes: Uint8Array): RemoteBulkMessage {
  if (bytes.length === 0) fail("header_too_short", "bulk");
  switch (bytes[0]) {
    case BULK_KIND_BEGIN: {
      if (bytes.length < 18) fail("header_too_short", "bulk");
      // Rust reads and validates the transfer id before it looks at
      // optionBits (`bulk.rs` decode_begin). A message that is invalid in both
      // ways must produce the same reason code in both languages.
      requireOpaqueId(bytes.slice(1, 17), "bulk_unknown_transfer", "bulk");
      const optionBits = bytes[17]!;
      let expected: number;
      let hasOptions: boolean;
      if (optionBits === BULK_OPTION_BITS_UNKNOWN) {
        expected = BULK_BEGIN_BYTES_WITHOUT_OPTIONS;
        hasOptions = false;
      } else if (optionBits === BULK_OPTION_BITS_KNOWN) {
        expected = BULK_BEGIN_BYTES_WITH_OPTIONS;
        hasOptions = true;
      } else {
        // 0x01, 0x02 and every other spelling are closed out.
        fail("bulk_option_bits", "bulk");
      }
      if (bytes.length !== expected) {
        fail(bytes.length < expected ? "bulk_length_mismatch" : "trailing_bytes", "bulk");
      }
      const transferId = bytes.slice(1, 17);
      let totalLength: bigint | undefined;
      let expectedSha256: Uint8Array | undefined;
      let cursor = 18;
      if (hasOptions) {
        totalLength = readU64Be(bytes, 18);
        expectedSha256 = bytes.slice(26, 58);
        cursor = 58;
      }
      const mimeClass = mimeClassFromCode(bytes[cursor]!);
      if (mimeClass === undefined) fail("bulk_unknown_mime_class", "bulk");
      const maxTotalLength = readU64Be(bytes, cursor + 1);
      const begin: RemoteBulkBegin = {
        kind: "begin",
        transferId,
        totalLength,
        expectedSha256,
        mimeClass,
        maxTotalLength,
      };
      // Rust validates on decode too; a begin that lies about its class limit
      // must not be accepted by one language and rejected by the other.
      validateBulkBegin(begin);
      return begin;
    }
    case BULK_KIND_CHUNK: {
      if (bytes.length < BULK_CHUNK_ENVELOPE_BYTES) fail("header_too_short", "bulk");
      const byteLength = readU32Be(bytes, 29);
      if (byteLength > MAX_BULK_CHUNK_PAYLOAD_BYTES) {
        fail("payload_cap_exceeded", "bulk", byteLength);
      }
      const actual = bytes.length - BULK_CHUNK_ENVELOPE_BYTES;
      if (actual > byteLength) fail("trailing_bytes", "bulk");
      if (actual < byteLength) fail("bulk_length_mismatch", "bulk");
      const chunkTransferId = bytes.slice(1, 17);
      requireOpaqueId(chunkTransferId, "bulk_unknown_transfer", "bulk");
      return {
        kind: "chunk",
        transferId: chunkTransferId,
        chunkIndex: readU32Be(bytes, 17),
        offset: readU64Be(bytes, 21),
        bytes: bytes.slice(BULK_CHUNK_ENVELOPE_BYTES),
      };
    }
    case BULK_KIND_COMPLETE: {
      if (bytes.length !== BULK_COMPLETE_BYTES) {
        fail(
          bytes.length < BULK_COMPLETE_BYTES ? "bulk_length_mismatch" : "trailing_bytes",
          "bulk",
        );
      }
      const completeTransferId = bytes.slice(1, 17);
      requireOpaqueId(completeTransferId, "bulk_unknown_transfer", "bulk");
      return {
        kind: "complete",
        transferId: completeTransferId,
        finalLength: readU64Be(bytes, 17),
        sha256: bytes.slice(25, 57),
      };
    }
    case BULK_KIND_ABORT: {
      if (bytes.length !== BULK_ABORT_BYTES) {
        fail(bytes.length < BULK_ABORT_BYTES ? "bulk_length_mismatch" : "trailing_bytes", "bulk");
      }
      // Rust validates the transfer id before the reason code (`bulk.rs`
      // decode_abort), so a doubly-invalid abort agrees across languages.
      const abortTransferId = bytes.slice(1, 17);
      requireOpaqueId(abortTransferId, "bulk_unknown_transfer", "bulk");
      const reason = abortReasonFromCode(bytes[17]!);
      if (reason === undefined) fail("bulk_unknown_abort_reason", "bulk");
      return { kind: "abort", transferId: abortTransferId, reason };
    }
    default:
      return fail("bulk_unknown_kind", "bulk");
  }
}

// --- carriers ---------------------------------------------------------------

/**
 * Which physical carrier moves a record.
 *
 * Mirrors Rust `RemoteCarrierKind`. Deliberately not reachable from the lane
 * reader/writer surface: application code must not branch on it.
 */
export type RemoteCarrierKind = "webrtc_data_channel" | "websocket_fallback";

/**
 * Both carriers *reserve* the 8-byte `peerSeenThrough` watermark; only the
 * fallback transmits it. That is the sole difference between them, which is
 * why fragment bytes are byte-identical on both.
 */
export function carrierTransmitsWatermark(kind: RemoteCarrierKind): boolean {
  return kind === "websocket_fallback";
}

/** Wrap an encoded fragment in its carrier record framing. */
export function encodeCarrierRecord(
  kind: RemoteCarrierKind,
  fragmentBytes: Uint8Array,
  peerSeenThrough: bigint,
): Uint8Array {
  if (fragmentBytes.length > LANE_FRAGMENT_TOTAL_BYTES) {
    fail("fragment_payload_cap_exceeded", undefined, fragmentBytes.length);
  }
  if (!carrierTransmitsWatermark(kind)) return fragmentBytes.slice();
  requireU64(peerSeenThrough);
  const record = new Uint8Array(PEER_SEEN_THROUGH_WATERMARK_BYTES + fragmentBytes.length);
  writeU64Be(record, 0, peerSeenThrough);
  record.set(fragmentBytes, PEER_SEEN_THROUGH_WATERMARK_BYTES);
  return record;
}

/** Strip the carrier record framing back to fragment bytes. */
export function decodeCarrierRecord(kind: RemoteCarrierKind, record: Uint8Array): Uint8Array {
  if (!carrierTransmitsWatermark(kind)) return record.slice();
  if (record.length < PEER_SEEN_THROUGH_WATERMARK_BYTES) fail("header_too_short");
  return record.slice(PEER_SEEN_THROUGH_WATERMARK_BYTES);
}

// --- classification ---------------------------------------------------------

export type RemoteMessageKind = "request" | "response" | "event";

export const REMOTE_MESSAGE_CLASSES = [
  "auth_completion",
  "capability_version",
  "lease_revocation",
  "liveness",
  "cancel",
  "resume_window",
  "bounded_request_response",
  "bounded_event",
  "terminal_io",
  "approval",
  "model_delta",
  "bulk_chunk",
] as const;
export type RemoteMessageClass = (typeof REMOTE_MESSAGE_CLASSES)[number];

/** The lane is a function of the class alone — no caller input exists. */
export const REMOTE_MESSAGE_CLASS_LANES: Readonly<Record<RemoteMessageClass, RemoteLane>> = {
  auth_completion: "control",
  capability_version: "control",
  lease_revocation: "control",
  liveness: "control",
  cancel: "control",
  resume_window: "control",
  bounded_request_response: "interactive",
  bounded_event: "interactive",
  terminal_io: "interactive",
  approval: "interactive",
  model_delta: "interactive",
  bulk_chunk: "bulk",
};

export type RemoteInlinePayloadBound =
  | "bounded"
  | "paged"
  | "truncated_by_cap"
  | "stream_chunked"
  | "bulk_reference";

export interface RemoteMessageClassification {
  readonly tag: string;
  readonly class: RemoteMessageClass;
  readonly lane: RemoteLane;
  readonly inlinePayloadBound: RemoteInlinePayloadBound;
}

export const UNKNOWN_MESSAGE_TAG = "__unknown";

/**
 * Look a tag up in a classification table. Unknown tags fail closed: there is
 * no default lane, so a new message kind cannot ride anything until it is
 * classified.
 */
export function classifyTag<T extends { readonly tag: string }>(
  table: readonly T[],
  tag: string,
): T {
  const row = table.find((candidate) => candidate.tag === tag);
  if (row === undefined || tag === UNKNOWN_MESSAGE_TAG) fail("unclassified_message");
  return row;
}

// --- fixed channel contract -------------------------------------------------

export interface RemoteLaneChannel {
  readonly lane: RemoteLane;
  readonly laneId: number;
  readonly channelId: number;
  readonly label: string;
  readonly negotiated: boolean;
  readonly ordered: boolean;
  readonly reliable: boolean;
  readonly compressed: boolean;
  readonly maxPayloadBytes: number;
}

export const REMOTE_LANE_CHANNELS: readonly RemoteLaneChannel[] = [
  {
    lane: "control",
    laneId: 0,
    channelId: 0,
    label: "flycockpit.control.v1",
    negotiated: true,
    ordered: true,
    reliable: true,
    compressed: false,
    maxPayloadBytes: REMOTE_LANE_MAX_PAYLOAD_BYTES.control,
  },
  {
    lane: "interactive",
    laneId: 1,
    channelId: 2,
    label: "flycockpit.interactive.v1",
    negotiated: true,
    ordered: true,
    reliable: true,
    compressed: false,
    maxPayloadBytes: REMOTE_LANE_MAX_PAYLOAD_BYTES.interactive,
  },
  {
    lane: "bulk",
    laneId: 2,
    channelId: 4,
    label: "flycockpit.bulk.v1",
    negotiated: true,
    ordered: true,
    reliable: true,
    compressed: false,
    maxPayloadBytes: REMOTE_LANE_MAX_PAYLOAD_BYTES.bulk,
  },
] as const;

export function laneForChannelId(channelId: number): RemoteLane {
  const channel = REMOTE_LANE_CHANNELS.find((candidate) => candidate.channelId === channelId);
  if (channel === undefined) fail("unknown_lane");
  return channel.lane;
}

export function laneForChannelLabel(label: string): RemoteLane {
  const channel = REMOTE_LANE_CHANNELS.find((candidate) => candidate.label === label);
  if (channel === undefined) fail("unknown_lane");
  return channel.lane;
}

// --- identifier helpers reused from the landed codec ------------------------

export function frameIdToText(frameId: Uint8Array): string {
  return encodeProtocolIdBase64Url(frameId);
}

export function frameIdFromText(text: string): Uint8Array {
  return decodeProtocolIdBase64Url(text);
}
