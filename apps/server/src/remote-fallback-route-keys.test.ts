import { describe, expect, it } from "vitest";
import {
  canRetireRemoteFallbackPreviousKey,
  parseRemoteFallbackRouteBindingKeys,
  remoteFallbackAttachmentBinding,
  remoteFallbackRouteBindingKeyDigest,
  validateRemoteFallbackRouteKeyWatermark,
} from "./remote-fallback-route-keys";

const file = {
  schemaVersion: 1,
  revision: "2",
  currentGeneration: "2",
  keys: [
    {
      generation: "1",
      keyBase64url: Buffer.alloc(32, 1).toString("base64url"),
      state: "previous",
      activatedAt: "1",
      retireAt: "999",
    },
    {
      generation: "2",
      keyBase64url: Buffer.alloc(32, 2).toString("base64url"),
      state: "current",
      activatedAt: "2",
      retireAt: null,
    },
  ],
} as const;

describe("remote fallback route-binding key lifecycle", () => {
  it("parses exact current/previous generations and makes keyed attachment bindings", () => {
    const parsed = parseRemoteFallbackRouteBindingKeys(file);
    expect(remoteFallbackRouteBindingKeyDigest(parsed)).toMatch(/^[0-9a-f]{64}$/);
    const first = remoteFallbackAttachmentBinding(
      parsed,
      "2",
      new Uint8Array(16).fill(3),
      new Uint8Array(16).fill(4),
    );
    const second = remoteFallbackAttachmentBinding(
      parsed,
      "1",
      new Uint8Array(16).fill(3),
      new Uint8Array(16).fill(4),
    );
    expect(first).toHaveLength(32);
    expect(Buffer.from(first).equals(Buffer.from(second))).toBe(false);
  });

  it("rejects rollback, changed accepted revisions, skipped generations and duplicate material", () => {
    const parsed = parseRemoteFallbackRouteBindingKeys(file);
    const watermark = validateRemoteFallbackRouteKeyWatermark(parsed, null);
    expect(() =>
      validateRemoteFallbackRouteKeyWatermark(
        { ...parsed, keys: parsed.keys.map((key) => ({ ...key, activatedAt: "9" })) },
        watermark,
      ),
    ).toThrow();
    expect(() =>
      parseRemoteFallbackRouteBindingKeys({ ...file, currentGeneration: "3" }),
    ).toThrow();
    expect(() =>
      parseRemoteFallbackRouteBindingKeys({
        ...file,
        keys: [file.keys[0], { ...file.keys[1], keyBase64url: file.keys[0].keyBase64url }],
      }),
    ).toThrow();
  });

  it("retains a previous key through the latest reference expiry plus sixty seconds", () => {
    const previous = parseRemoteFallbackRouteBindingKeys(file).keys[0]!;
    expect(
      canRetireRemoteFallbackPreviousKey({
        key: previous,
        nowMillis: 60_999n,
        latestReferencedExpiryMillis: 1_000n,
      }),
    ).toBe(false);
    expect(
      canRetireRemoteFallbackPreviousKey({
        key: previous,
        nowMillis: 61_000n,
        latestReferencedExpiryMillis: 1_000n,
      }),
    ).toBe(true);
  });
});
