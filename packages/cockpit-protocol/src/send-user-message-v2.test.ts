import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  attachmentSetDigest,
  decodeCanonicalSendUserMessageV2,
  encodeCanonicalSendUserMessageV2,
  hasMessageText,
  messageRequestDigest,
  FCM2_MAX_BYTES,
  validateFcm2Length,
} from "./send-user-message-v2";

const fixture = JSON.parse(
  readFileSync(
    new URL("../fixtures/send-user-message-v2-canonical-vectors.json", import.meta.url),
    "utf8",
  ),
);
const fromHex = (value: string) =>
  Uint8Array.from(value.match(/../g)!, (pair) => Number.parseInt(pair, 16));
const toHex = (value: Uint8Array) =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");

describe("send_user_message_v2_canonical_vectors", () => {
  it("round trips the shared bytes and digests", async () => {
    for (const vector of fixture.vectors) {
      const bytes = fromHex(vector.fcm2_hex);
      const decoded = decodeCanonicalSendUserMessageV2(bytes);
      expect(toHex(encodeCanonicalSendUserMessageV2(decoded)), vector.name).toBe(vector.fcm2_hex);
      expect(toHex(await messageRequestDigest(decoded)), vector.name).toBe(
        vector.message_request_digest_hex,
      );
      expect(toHex(await attachmentSetDigest(decoded)), vector.name).toBe(
        vector.attachment_set_digest_hex,
      );
    }
  });

  it("rejects every shared malformed byte sequence", () => {
    for (const malformed of fixture.malformed_fcm2)
      expect(
        () => decodeCanonicalSendUserMessageV2(fromHex(malformed.fcm2_hex)),
        malformed.name,
      ).toThrow();
  });

  it("uses the exact scalar predicate and rejects unpaired surrogates", () => {
    for (const vector of fixture.predicate_vectors)
      expect(hasMessageText(vector.text)).toBe(vector.has_message_text);
    expect(() => hasMessageText("\ud800")).toThrow(/surrogate/);
  });

  it("rejects noncanonical UUIDs and out-of-range u64 values", () => {
    const decoded = decodeCanonicalSendUserMessageV2(fromHex(fixture.vectors[0].fcm2_hex));
    expect(() =>
      encodeCanonicalSendUserMessageV2({
        ...decoded,
        session_id: decoded.session_id.toUpperCase(),
      }),
    ).toThrow(/canonical/);
    expect(() =>
      encodeCanonicalSendUserMessageV2({ ...decoded, model_config_generation: 1n << 64n }),
    ).toThrow(/u64/);
  });

  it("encodes the exact maximum and rejects cap plus one before allocation", () => {
    const scalarMax = "😀".repeat(262_144);
    const decoded = decodeCanonicalSendUserMessageV2(fromHex(fixture.vectors[0].fcm2_hex));
    const maximum = {
      ...decoded,
      model_config_generation: 0xffffffffffffffffn,
      request: {
        ...decoded.request,
        text: scalarMax,
        display_text: scalarMax,
        tag_expansions: Array.from({ length: 64 }, () => ({
          tool: "t".repeat(128),
          path: "p".repeat(4096),
          detail: "d".repeat(4096),
          ok: true,
        })),
        forced_skill: "s".repeat(128),
        attachments: Array.from({ length: 16 }, (_, index) => ({
          attachment_id: `00000000-0000-4000-8000-${(index + 1).toString(16).padStart(12, "0")}`,
          attachment_version: 0xffffffffffffffffn,
          checksum: new Uint8Array(32).fill(index),
          kind: (["image", "audio", "video"] as const)[index % 3]!,
        })),
      },
    };
    expect(encodeCanonicalSendUserMessageV2(maximum)).toHaveLength(FCM2_MAX_BYTES);
    expect(() => validateFcm2Length(FCM2_MAX_BYTES + 1)).toThrow(/maximum/);
  });
});
