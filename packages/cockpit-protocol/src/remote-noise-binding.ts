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
