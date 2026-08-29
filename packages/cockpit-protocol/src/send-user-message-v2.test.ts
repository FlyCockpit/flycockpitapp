import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { CanonicalSendUserMessageV2 } from "./send-user-message-v2";
import {
  attachmentSetDigest,
  decodeCanonicalSendUserMessageV2,
  encodeCanonicalSendUserMessageV2,
  FCM2_MAX_BYTES,
  FCM2_MAX_CURRENT_ENCODING_BYTES,
  FCM2_MAX_TEXT_BYTES,
  FCM2_MAX_TEXT_SCALARS,
  hasMessageText,
  messageRequestDigest,
  validateAuthenticatedRemoteMessageV2,
  validateFcm2Length,
  validateLocalOwnerDirectMessageV2,
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
function exactError(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(Error);
    return (error as Error).message;
  }
  throw new Error("expected action to throw");
}
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
  it("matches the shared protocol-limit fixture", () => {
    expect(fixture.limits).toEqual({
      fcm2_max_bytes: FCM2_MAX_BYTES,
      fcm2_max_current_encoding_bytes: FCM2_MAX_CURRENT_ENCODING_BYTES,
      text_max_bytes: FCM2_MAX_TEXT_BYTES,
      text_max_scalars: FCM2_MAX_TEXT_SCALARS,
    });
  });

  it("validates distinct UUIDv7 transport and operation identities", () => {
    const request = decodeCanonicalSendUserMessageV2(fromHex(fixture.vectors[0].fcm2_hex)).request;
    const envelope = validateLocalOwnerDirectMessageV2({
      ingress: "local_owner_direct",
      request_id: "018f47a2-7b3c-7def-8123-000000000001",
      operation_id: "018f47a2-7b3c-7def-8123-000000000002",
      session_locator: "opaque-session",
      request,
    });
    expect(envelope.operation_id).not.toBe(request.client_submission_id);
    expect(
      exactError(() =>
        validateLocalOwnerDirectMessageV2({
          ingress: "local_owner_direct",
          request_id: envelope.operation_id,
          operation_id: envelope.operation_id,
          session_locator: envelope.session_locator,
          request,
        }),
      ),
    ).toBe("request, operation, and submission identities must be pairwise distinct");
    const requestCollision = structuredClone(request);
    requestCollision.client_submission_id = envelope.request_id;
    expect(
      exactError(() =>
        validateLocalOwnerDirectMessageV2({
          ingress: "local_owner_direct",
          request_id: envelope.request_id,
          operation_id: envelope.operation_id,
          session_locator: envelope.session_locator,
          request: requestCollision,
        }),
      ),
    ).toBe("request, operation, and submission identities must be pairwise distinct");
    const operationCollision = structuredClone(request);
    operationCollision.client_submission_id = envelope.operation_id;
    expect(
      exactError(() =>
        validateLocalOwnerDirectMessageV2({
          ingress: "local_owner_direct",
          request_id: envelope.request_id,
          operation_id: envelope.operation_id,
          session_locator: envelope.session_locator,
          request: operationCollision,
        }),
      ),
    ).toBe("request, operation, and submission identities must be pairwise distinct");
    expect(
      exactError(() =>
        validateLocalOwnerDirectMessageV2({
          ingress: "local_owner_direct",
          request_id: "018f47a2-7b3c-7def-0123-000000000003",
          operation_id: envelope.operation_id,
          session_locator: envelope.session_locator,
          request,
        }),
      ),
    ).toBe("request_id must be UUIDv7");
    const remote = validateAuthenticatedRemoteMessageV2(
      {
        ingress: "authenticated_remote",
        request_id: envelope.request_id,
        operation_id: envelope.operation_id,
        session_locator: envelope.session_locator,
        request,
      },
      { id: new Uint8Array(16).fill(42), generation: 9n },
    );
    expect(remote.ingress).toBe("authenticated_remote");
    expect(remote.actor).toEqual({
      kind: "remote_device",
      id: new Uint8Array(16).fill(42),
      generation: 9n,
    });
  });

  it("rejects daemon-owned provenance at both ingress boundaries", () => {
    const request = decodeCanonicalSendUserMessageV2(fromHex(fixture.vectors[0].fcm2_hex)).request;
    request.origin = "auto_continue";
    const envelope = {
      request_id: "018f47a2-7b3c-7def-8123-000000000001",
      operation_id: "018f47a2-7b3c-7def-8123-000000000002",
      session_locator: "opaque-session",
      request,
    };
    expect(() =>
      validateLocalOwnerDirectMessageV2({ ...envelope, ingress: "local_owner_direct" }),
    ).toThrow("user-message ingress origin must be external_root");
    expect(() =>
      validateAuthenticatedRemoteMessageV2(
        { ...envelope, ingress: "authenticated_remote" },
        { id: new Uint8Array(16).fill(42), generation: 9n },
      ),
    ).toThrow("user-message ingress origin must be external_root");
  });
  it("round trips the shared bytes and digests", async () => {
    for (const vector of [...fixture.vectors, ...fixture.compact_positive_vectors]) {
      const bytes = vector.fcm2_hex ? fromHex(vector.fcm2_hex) : compactBytes(vector);
      const decoded = decodeCanonicalSendUserMessageV2(bytes);
      expect(decoded.request.origin, vector.name).toBe("external_root");
      expect(toHex(encodeCanonicalSendUserMessageV2(decoded)), vector.name).toBe(toHex(bytes));
      expect(toHex(await messageRequestDigest(decoded)), vector.name).toBe(
        vector.message_request_digest_hex,
      );
      expect(toHex(await attachmentSetDigest(decoded)), vector.name).toBe(
        vector.attachment_set_digest_hex,
      );
    }
  });

  it("rejects daemon-owned provenance from canonical encode and decode", () => {
    const external = decodeCanonicalSendUserMessageV2(fromHex(fixture.vectors[1].fcm2_hex));
    const internal = structuredClone(external);
    internal.request.origin = "auto_continue";
    expect(() => encodeCanonicalSendUserMessageV2(internal)).toThrow(
      "FCM2 user-message origin must be external_root",
    );

    const internalBytes = fromHex(fixture.vectors[1].fcm2_hex);
    internalBytes[21] = 4;
    expect(() => decodeCanonicalSendUserMessageV2(internalBytes)).toThrow(
      "FCM2 user-message origin must be external_root",
    );
  });

  it("rejects shared semantic mutations with exact errors", () => {
    const base = decodeCanonicalSendUserMessageV2(fromHex(fixture.vectors[1].fcm2_hex));
    for (const testCase of fixture.semantic_error_cases) {
      const value = structuredClone(base);
      const tag = value.request.tag_expansions[0];
      if (!tag) throw new Error("semantic fixture requires one tag expansion");
      if (testCase.mutation === "empty_tool") tag.tool = "";
      else if (testCase.mutation === "detail_one_over") tag.detail = "d".repeat(4097);
      else if (testCase.mutation === "empty_skill") value.request.forced_skill = "";
      else if (testCase.mutation === "invalid_skill") value.request.forced_skill = "bad/skill";
      else if (testCase.mutation === "multibyte_tool") tag.tool = "é".repeat(65);
      expect(
        exactError(() => encodeCanonicalSendUserMessageV2(value)),
        testCase.name,
      ).toBe(testCase.error_code);
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
        session_id: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
      }),
    ).toThrow(/canonical/);
    expect(() =>
      encodeCanonicalSendUserMessageV2({ ...decoded, model_config_generation: 1n << 64n }),
    ).toThrow(/u64/);
  });

  it("encodes the exact maximum and rejects cap plus one before allocation", () => {
    const scalarMax = "a".repeat(8_388_608);
    const decoded = decodeCanonicalSendUserMessageV2(fromHex(fixture.vectors[0].fcm2_hex));
    const maximum: CanonicalSendUserMessageV2 = {
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
        resolved_delivery_class: "held",
        resolved_queue_target: {
          id: "i".repeat(4096),
          agent: "a".repeat(1024),
          depth: (1n << 64n) - 1n,
          task_call_id: "t".repeat(4096),
        },
        attachments: Array.from({ length: 16 }, (_, index) => ({
          attachment_id: `00000000-0000-4000-8000-${(index + 1).toString(16).padStart(12, "0")}`,
          attachment_version: 0xffffffffffffffffn,
          checksum: new Uint8Array(32).fill(index),
          kind: (["image", "audio", "video"] as const)[index % 3]!,
        })),
      },
    };
    expect(encodeCanonicalSendUserMessageV2(maximum)).toHaveLength(FCM2_MAX_CURRENT_ENCODING_BYTES);
    expect(() => validateFcm2Length(FCM2_MAX_BYTES)).not.toThrow();
    expect(() => decodeCanonicalSendUserMessageV2(new Uint8Array(FCM2_MAX_BYTES + 1))).toThrow(
      "FCM2 exceeds maximum size",
    );
    maximum.request.text += "a";
    expect(() => encodeCanonicalSendUserMessageV2(maximum)).toThrow("text exceeds byte limit");
    // Four-byte scalars exhaust the byte budget before the scalar ceiling.
    maximum.request.text = "😀".repeat(2_097_153);
    expect(() => encodeCanonicalSendUserMessageV2(maximum)).toThrow("text exceeds byte limit");
    maximum.request.text = "x";
    maximum.request.display_text = `${scalarMax}a`;
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
    expect(exactError(() => encodeCanonicalSendUserMessageV2(maximum))).toBe(
      "fcm2_tag_tool_too_long",
    );
    maximum.request.tag_expansions[0]!.tool = "t";
    maximum.request.tag_expansions[0]!.path += "p";
    expect(exactError(() => encodeCanonicalSendUserMessageV2(maximum))).toBe(
      "fcm2_tag_path_too_long",
    );
    maximum.request.tag_expansions[0]!.path = "p";
    maximum.request.forced_skill += "s";
    expect(exactError(() => encodeCanonicalSendUserMessageV2(maximum))).toBe(
      "fcm2_forced_skill_too_long",
    );
    expect(() => validateFcm2Length(FCM2_MAX_BYTES + 1)).toThrow(/maximum/);
  });
});
