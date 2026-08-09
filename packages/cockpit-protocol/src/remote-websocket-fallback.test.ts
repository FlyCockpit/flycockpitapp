import { describe, expect, it } from "vitest";
import {
  decodeRemoteFallbackAckV1,
  decodeRemoteFallbackAuthV1,
  decodeRemoteFallbackChallengeV1,
  decodeRemoteFallbackOuterRecordV1,
  encodeRemoteFallbackAckV1,
  encodeRemoteFallbackAuthV1,
  encodeRemoteFallbackChallengeV1,
  encodeRemoteFallbackOuterRecordV1,
  REMOTE_FALLBACK_ACK_NONE,
  REMOTE_FALLBACK_AUTH_MAX_BYTES,
  REMOTE_FALLBACK_MAX_MESSAGE_BYTES,
  remoteFallbackSocketAuthDigest,
} from "./remote-websocket-fallback";

const bytes = (length: number, value: number) => new Uint8Array(length).fill(value);

describe("remote WebSocket fallback wire", () => {
  it("uses exact FCDF/FCFA bounds and signing domain inputs", () => {
    const challenge = encodeRemoteFallbackChallengeV1({
      challenge: bytes(32, 1),
      issuedAt: 10n,
      expiresAt: 20n,
    });
    expect(challenge).toHaveLength(53);
    expect(decodeRemoteFallbackChallengeV1(challenge).expiresAt).toBe(20n);
    const auth = encodeRemoteFallbackAuthV1({
      ticketId: bytes(16, 2),
      ticketSecret: bytes(32, 3),
      certificateJws: bytes(4096, 4),
      connectionNonce: bytes(32, 5),
      signature: bytes(64, 6),
    });
    expect(auth).toHaveLength(REMOTE_FALLBACK_AUTH_MAX_BYTES);
    expect(decodeRemoteFallbackAuthV1(auth).certificateJws).toHaveLength(4096);
    const digest = remoteFallbackSocketAuthDigest({
      challengeFrame: challenge,
      role: "client",
      childAttemptId: bytes(16, 7),
      transportEpoch: bytes(16, 8),
      authFrame: auth,
    });
    expect(digest).toHaveLength(32);
    const changed = remoteFallbackSocketAuthDigest({
      challengeFrame: challenge,
      role: "daemon",
      childAttemptId: bytes(16, 7),
      transportEpoch: bytes(16, 8),
      authFrame: auth,
    });
    expect(Buffer.from(changed).equals(Buffer.from(digest))).toBe(false);
  });

  it("round trips the exact 28-byte opaque outer header", () => {
    const encoded = encodeRemoteFallbackOuterRecordV1({
      routeGeneration: 1n,
      direction: "client_to_daemon",
      recordSequence: 2n,
      peerSeenThrough: REMOTE_FALLBACK_ACK_NONE,
      ciphertext: bytes(65_535, 9),
    });
    expect(encoded).toHaveLength(REMOTE_FALLBACK_MAX_MESSAGE_BYTES);
    expect(Array.from(encoded.slice(0, 10))).toEqual([1, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    expect(decodeRemoteFallbackOuterRecordV1(encoded)).toMatchObject({
      routeGeneration: 1n,
      recordSequence: 2n,
      peerSeenThrough: REMOTE_FALLBACK_ACK_NONE,
    });
    expect(() => decodeRemoteFallbackOuterRecordV1(new Uint8Array([...encoded, 0]))).toThrow(
      "invalid_outer_record",
    );
  });

  it("uses the exact cumulative ACK sentinel without a bitmap", () => {
    const ack = encodeRemoteFallbackAckV1(REMOTE_FALLBACK_ACK_NONE);
    expect(ack).toHaveLength(9);
    expect(Array.from(ack)).toEqual([1, 255, 255, 255, 255, 255, 255, 255, 255]);
    expect(decodeRemoteFallbackAckV1(ack)).toBe(REMOTE_FALLBACK_ACK_NONE);
  });
});
