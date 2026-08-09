import { describe, expect, it } from "vitest";
import {
  assertRemoteNoiseCiphertextRecord,
  assertRemoteNoiseHandshakeFrame,
  decodeRemoteNoiseFallbackByteList,
  decodeRemoteNoiseFallbackObserve,
  REMOTE_NOISE_CIPHERTEXT_MAX_BYTES,
} from "./remote-noise-binding";

describe("remote Noise transport-only DTOs", () => {
  it("accepts bounded opaque bytes without exposing cryptographic operations", () => {
    expect(() =>
      assertRemoteNoiseHandshakeFrame({ messageIndex: 1, bytes: new Uint8Array(36) }),
    ).not.toThrow();
    expect(() =>
      assertRemoteNoiseCiphertextRecord({
        absoluteSequence: 0n,
        bytes: new Uint8Array(REMOTE_NOISE_CIPHERTEXT_MAX_BYTES),
      }),
    ).not.toThrow();
  });

  it("rejects oversized and reconnect-boundary records", () => {
    expect(() =>
      assertRemoteNoiseHandshakeFrame({ messageIndex: 2, bytes: new Uint8Array(4101) }),
    ).toThrow();
    expect(() =>
      assertRemoteNoiseCiphertextRecord({ absoluteSequence: 1n << 32n, bytes: new Uint8Array() }),
    ).toThrow();
  });

  it("strictly decodes opaque fallback binding framing", () => {
    expect(
      decodeRemoteNoiseFallbackObserve(new Uint8Array([0, 1, 0, 0, 0, 0, 0, 0, 0, 0])),
    ).toEqual({
      status: "buffered",
      acknowledge: new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0, 0]),
    });
    expect(
      decodeRemoteNoiseFallbackObserve(new Uint8Array([2, 0, 0, 1, 0, 0, 0, 2, 7, 8])),
    ).toEqual({ status: "contiguous", gapFilled: false, records: [new Uint8Array([7, 8])] });
    expect(decodeRemoteNoiseFallbackByteList(new Uint8Array([0, 0]))).toEqual([]);
  });

  it("rejects malformed fallback binding framing", () => {
    expect(() => decodeRemoteNoiseFallbackObserve(new Uint8Array([0]))).toThrow();
    expect(() => decodeRemoteNoiseFallbackObserve(new Uint8Array([2, 2, 0, 0]))).toThrow();
    expect(() =>
      decodeRemoteNoiseFallbackByteList(new Uint8Array([0, 1, 0, 0, 0, 2, 7])),
    ).toThrow();
    expect(() => decodeRemoteNoiseFallbackByteList(new Uint8Array([0, 0, 1]))).toThrow();
  });
});
