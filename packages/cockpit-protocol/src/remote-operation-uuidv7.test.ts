import { describe, expect, it } from "vitest";
import fixture from "../fixtures/remote-operation-uuidv7-v1.json" with { type: "json" };
import {
  generateRemoteOperationUuidV7,
  MAX_UUID_V7_UNIX_MS,
  remoteOperationIdentityV1Schema,
} from "./index";

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Deterministic `getRandomValues` that copies fixed bytes into the buffer. */
function fixedRandom(hex: string): (bytes: Uint8Array) => void {
  const source = hexToBytes(hex);
  return (bytes) => {
    bytes.set(source.subarray(0, bytes.length));
  };
}

describe("generateRemoteOperationUuidV7", () => {
  it("matches the shared Rust/TypeScript byte-identity vectors", () => {
    expect(fixture.schemaVersion).toBe(1);
    expect(fixture.vectors.length).toBeGreaterThan(0);
    for (const vector of fixture.vectors) {
      const id = generateRemoteOperationUuidV7({
        nowMs: vector.unixMs,
        getRandomValues: fixedRandom(vector.randomHex),
      });
      expect(id).toBe(vector.expected);
      // Version nibble and RFC variant are stamped regardless of random bits.
      expect(id[14]).toBe("7");
      expect(["8", "9", "a", "b"]).toContain(id[19]);
      // The generated id is accepted by the strict operation-identity schema.
      expect(
        remoteOperationIdentityV1Schema.safeParse({
          schemaVersion: 1,
          logicalAttachmentId: "22222222-2222-4222-8222-222222222222",
          operationId: id,
        }).success,
      ).toBe(true);
    }
  });

  it("rejects every out-of-range timestamp in the shared fixture", () => {
    expect(fixture.rejectedUnixMs.length).toBeGreaterThan(0);
    for (const rejected of fixture.rejectedUnixMs) {
      expect(() =>
        generateRemoteOperationUuidV7({
          nowMs: rejected.unixMs,
          getRandomValues: fixedRandom("00000000000000000000000000000000"),
        }),
      ).toThrow(RangeError);
    }
  });

  it("rejects negative, fractional, and non-finite timestamps", () => {
    const random = fixedRandom("00000000000000000000000000000000");
    for (const nowMs of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, MAX_UUID_V7_UNIX_MS + 1]) {
      expect(() => generateRemoteOperationUuidV7({ nowMs, getRandomValues: random })).toThrow(
        RangeError,
      );
    }
  });

  it("re-rolls the random bits on a collision before first submission", () => {
    const first = "0123456789abcdeffedcba9876543210";
    const second = "112233445566778899aabbccddeeff00";
    const draws = [first, second];
    const getRandomValues = (bytes: Uint8Array) => {
      const hex = draws.shift();
      if (hex === undefined) {
        throw new Error("unexpected extra random draw");
      }
      bytes.set(hexToBytes(hex).subarray(0, bytes.length));
    };
    const collidingId = generateRemoteOperationUuidV7({
      nowMs: 1704067200000,
      getRandomValues: fixedRandom(first),
    });
    const id = generateRemoteOperationUuidV7({
      nowMs: 1704067200000,
      getRandomValues,
      seen: new Set([collidingId]),
    });
    expect(id).not.toBe(collidingId);
    expect(draws.length).toBe(0); // both draws consumed: one collision, one accepted
  });

  it("fails closed when collisions cannot be resolved within maxAttempts", () => {
    expect(() =>
      generateRemoteOperationUuidV7({
        nowMs: 1704067200000,
        getRandomValues: fixedRandom("0123456789abcdeffedcba9876543210"),
        seen: { has: () => true },
        maxAttempts: 4,
      }),
    ).toThrow(/collision-free/);
  });

  it("rejects a non-finite / non-integer maxAttempts so the cap stays bounded", () => {
    for (const bad of [Number.POSITIVE_INFINITY, 0, -1, 2.5, Number.NaN]) {
      expect(() =>
        generateRemoteOperationUuidV7({
          nowMs: 1704067200000,
          getRandomValues: fixedRandom("0123456789abcdeffedcba9876543210"),
          seen: { has: () => true },
          maxAttempts: bad,
        }),
      ).toThrow(/maxAttempts must be a positive integer/);
    }
  });

  it("produces schema-valid identities from a live clock and CSPRNG", () => {
    const id = generateRemoteOperationUuidV7({
      nowMs: Date.now(),
      getRandomValues: (bytes) => globalThis.crypto.getRandomValues(bytes),
    });
    expect(id[14]).toBe("7");
    expect(
      remoteOperationIdentityV1Schema.safeParse({
        schemaVersion: 1,
        logicalAttachmentId: "22222222-2222-4222-8222-222222222222",
        operationId: id,
      }).success,
    ).toBe(true);
  });
});
