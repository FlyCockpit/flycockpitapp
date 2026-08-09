/** Transport-only constants shared with the Rust-owned Noise binding. */
export const REMOTE_NOISE_HANDSHAKE_VERSION = 1 as const;
export const REMOTE_NOISE_HANDSHAKE_HEADER_BYTES = 4 as const;
export const REMOTE_NOISE_HANDSHAKE_MESSAGE_MAX_BYTES = 4096 as const;
export const REMOTE_NOISE_CIPHERTEXT_MAX_BYTES = 65_535 as const;
export const REMOTE_NOISE_LANE_FRAGMENT_MAX_BYTES = 65_497 as const;
export const REMOTE_NOISE_LANE_FRAGMENT_PAYLOAD_MAX_BYTES = 65_471 as const;

export type RemoteNoiseHandshakeMessageIndex = 1 | 2;
export type RemoteNoiseOpaqueHandle = bigint;

export interface RemoteNoiseHandshakeFrame {
  readonly messageIndex: RemoteNoiseHandshakeMessageIndex;
  /** Opaque bytes produced by the Rust binding. Never decode as text. */
  readonly bytes: Uint8Array;
}

export interface RemoteNoiseCiphertextRecord {
  /** Bounded carrier copy; Rust rejects a mismatch after authentication. */
  readonly absoluteSequence: bigint;
  /** Opaque ciphertext produced by the Rust binding. */
  readonly bytes: Uint8Array;
}

export type RemoteNoiseFallbackObserveResult =
  | { readonly status: "buffered" | "duplicate"; readonly acknowledge: Uint8Array }
  | {
      readonly status: "contiguous";
      readonly gapFilled: boolean;
      readonly acknowledge?: Uint8Array;
      readonly records: readonly Uint8Array[];
    };

const FALLBACK_ACK_BYTES = 9;
const FALLBACK_RECORD_MAX_BYTES = 65_563;
const FALLBACK_WINDOW_MAX_RECORDS = 64;

/** Decode only the length framing emitted by the Rust fallback binding. */
export function decodeRemoteNoiseFallbackByteList(bytes: Uint8Array): readonly Uint8Array[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.byteLength < 2) throw new Error("invalid_remote_noise_fallback_binding");
  const count = view.getUint16(0, false);
  if (count > FALLBACK_WINDOW_MAX_RECORDS) {
    throw new Error("invalid_remote_noise_fallback_binding");
  }
  let offset = 2;
  const records: Uint8Array[] = [];
  for (let index = 0; index < count; index += 1) {
    if (offset + 4 > bytes.byteLength) throw new Error("invalid_remote_noise_fallback_binding");
    const length = view.getUint32(offset, false);
    offset += 4;
    if (length > FALLBACK_RECORD_MAX_BYTES || offset + length > bytes.byteLength) {
      throw new Error("invalid_remote_noise_fallback_binding");
    }
    records.push(bytes.slice(offset, offset + length));
    offset += length;
  }
  if (offset !== bytes.byteLength) throw new Error("invalid_remote_noise_fallback_binding");
  return records;
}

/** Decode the discriminant/framing only; ACKs and records remain opaque Rust-owned bytes. */
export function decodeRemoteNoiseFallbackObserve(
  bytes: Uint8Array,
): RemoteNoiseFallbackObserveResult {
  const status = bytes[0];
  if (status === 0 || status === 1) {
    if (bytes.byteLength !== 1 + FALLBACK_ACK_BYTES) {
      throw new Error("invalid_remote_noise_fallback_binding");
    }
    return {
      status: status === 0 ? "buffered" : "duplicate",
      acknowledge: bytes.slice(1),
    };
  }
  if (status !== 2 || bytes.byteLength < 4 || (bytes[1] !== 0 && bytes[1] !== 1)) {
    throw new Error("invalid_remote_noise_fallback_binding");
  }
  const gapFilled = bytes[1] === 1;
  const listOffset = gapFilled ? 2 + FALLBACK_ACK_BYTES : 2;
  if (bytes.byteLength < listOffset + 2) {
    throw new Error("invalid_remote_noise_fallback_binding");
  }
  const records = decodeRemoteNoiseFallbackByteList(bytes.slice(listOffset));
  return {
    status: "contiguous",
    gapFilled,
    ...(gapFilled ? { acknowledge: bytes.slice(2, listOffset) } : {}),
    records,
  };
}

export function assertRemoteNoiseHandshakeFrame(frame: RemoteNoiseHandshakeFrame): void {
  if (
    (frame.messageIndex !== 1 && frame.messageIndex !== 2) ||
    frame.bytes.byteLength < REMOTE_NOISE_HANDSHAKE_HEADER_BYTES ||
    frame.bytes.byteLength >
      REMOTE_NOISE_HANDSHAKE_HEADER_BYTES + REMOTE_NOISE_HANDSHAKE_MESSAGE_MAX_BYTES
  ) {
    throw new Error("invalid_remote_noise_handshake_frame");
  }
}

export function assertRemoteNoiseCiphertextRecord(record: RemoteNoiseCiphertextRecord): void {
  if (
    record.absoluteSequence < 0n ||
    record.absoluteSequence >= 1n << 32n ||
    record.bytes.byteLength > REMOTE_NOISE_CIPHERTEXT_MAX_BYTES
  ) {
    throw new Error("invalid_remote_noise_ciphertext_record");
  }
}
