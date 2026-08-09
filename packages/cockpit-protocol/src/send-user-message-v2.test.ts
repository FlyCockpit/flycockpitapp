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
function compactBytes(vector: {
  segments?: { hex: string; repeat: number }[];
  prefix_hex?: string;
  generated_attachments?: number;
}) {
  const parts: Uint8Array[] = [];
  if (vector.segments)
    for (const segment of vector.segments)
      for (let i = 0; i < segment.repeat; i++) parts.push(fromHex(segment.hex));
  else {
    parts.push(fromHex(vector.prefix_hex!));
    for (let i = 1; i <= vector.generated_attachments!; i++) {
      parts.push(fromHex(`00000000000040008000${i.toString(16).padStart(12, "0")}`));
      const version = new Uint8Array(8);
      new DataView(version.buffer).setBigUint64(0, BigInt(i));
      parts.push(version, new Uint8Array(32).fill(i), Uint8Array.of(((i - 1) % 3) + 1));
    }
  }
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

describe("send_user_message_v2_canonical_vectors", () => {
  it("round trips the shared bytes and digests", async () => {
    for (const vector of [...fixture.vectors, ...fixture.compact_positive_vectors]) {
      const bytes = vector.fcm2_hex ? fromHex(vector.fcm2_hex) : compactBytes(vector);
      const decoded = decodeCanonicalSendUserMessageV2(bytes);
      expect(toHex(encodeCanonicalSendUserMessageV2(decoded)), vector.name).toBe(toHex(bytes));
      expect(toHex(await messageRequestDigest(decoded)), vector.name).toBe(
        vector.message_request_digest_hex,
      );
      expect(toHex(await attachmentSetDigest(decoded)), vector.name).toBe(
        vector.attachment_set_digest_hex,
      );
    }
  });

  it("rejects shared semantic mutations with exact errors", () => {
    const base = decodeCanonicalSendUserMessageV2(fromHex(fixture.vectors[1].fcm2_hex));
    for (const testCase of fixture.semantic_error_cases) {
      const value = structuredClone(base);
      if (testCase.mutation === "empty_tool") value.request.tag_expansions[0].tool = "";
      else if (testCase.mutation === "detail_one_over")
        value.request.tag_expansions[0].detail = "d".repeat(4097);
      else if (testCase.mutation === "empty_skill") value.request.forced_skill = "";
      else if (testCase.mutation === "invalid_skill") value.request.forced_skill = "bad/skill";
      else if (testCase.mutation === "multibyte_tool")
        value.request.tag_expansions[0].tool = "é".repeat(65);
      expect(() => encodeCanonicalSendUserMessageV2(value), testCase.name).toThrow(
        testCase.error_code,
      );
    }
  });

  it("rejects every shared malformed byte sequence", () => {
    for (const malformed of fixture.malformed_fcm2)
      expect(
        () => decodeCanonicalSendUserMessageV2(fromHex(malformed.fcm2_hex)),
        malformed.name,
      ).toThrow(malformed.error);
    for (const malformed of fixture.mutation_cases) {
      const bytes = fromHex(fixture.vectors[malformed.source].fcm2_hex);
      if (malformed.offset !== undefined) bytes.set(fromHex(malformed.bytes_hex), malformed.offset);
      const input = malformed.truncate === undefined ? bytes : bytes.slice(0, malformed.truncate);
      expect(() => decodeCanonicalSendUserMessageV2(input), malformed.name).toThrow(
        malformed.error,
      );
    }
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
    expect(() => decodeCanonicalSendUserMessageV2(new Uint8Array(FCM2_MAX_BYTES + 1))).toThrow(
      "FCM2 exceeds maximum size",
    );
    maximum.request.text += "😀";
    expect(() => encodeCanonicalSendUserMessageV2(maximum)).toThrow("text exceeds byte limit");
    maximum.request.text = "a".repeat(262_145);
    expect(() => encodeCanonicalSendUserMessageV2(maximum)).toThrow("text exceeds scalar limit");
    maximum.request.text = "x";
    maximum.request.display_text = `${scalarMax}😀`;
    expect(() => encodeCanonicalSendUserMessageV2(maximum)).toThrow(
      "display text exceeds byte limit",
    );
    maximum.request.display_text = null;
    maximum.request.tag_expansions.push(maximum.request.tag_expansions[0]!);
    expect(() => encodeCanonicalSendUserMessageV2(maximum)).toThrow("too many tags");
    maximum.request.tag_expansions.pop();
    maximum.request.attachments.push(maximum.request.attachments[0]!);
    expect(() => encodeCanonicalSendUserMessageV2(maximum)).toThrow("too many attachments");
    maximum.request.attachments.pop();
    maximum.request.tag_expansions[0]!.tool += "t";
    expect(() => encodeCanonicalSendUserMessageV2(maximum)).toThrow("fcm2_tag_tool_too_long");
    maximum.request.tag_expansions[0]!.tool = "t";
    maximum.request.tag_expansions[0]!.path += "p";
    expect(() => encodeCanonicalSendUserMessageV2(maximum)).toThrow("fcm2_tag_path_too_long");
    maximum.request.tag_expansions[0]!.path = "p";
    maximum.request.forced_skill += "s";
    expect(() => encodeCanonicalSendUserMessageV2(maximum)).toThrow("fcm2_forced_skill_too_long");
    expect(() => validateFcm2Length(FCM2_MAX_BYTES + 1)).toThrow(/maximum/);
  });
});
