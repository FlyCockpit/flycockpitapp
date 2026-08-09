import { describe, expect, it } from "vitest";
import {
  assertRemoteNoiseCiphertextRecord,
  assertRemoteNoiseHandshakeFrame,
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
});
