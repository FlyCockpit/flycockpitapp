import { describe, expect, it } from "vitest";
import vector from "../fixtures/remote-operation-fcor-v1.json" with { type: "json" };
import {
  CanonicalParamsV1,
  checkedFcorV1Size,
  encodeFcorV1,
  hashFcorV1,
  validateRegisteredSendUserMessageV2,
  validateFcorV1,
} from "./remote-operation-fcor";

describe("FCOR v1", () => {
  it("matches the shared canonical vector and digest exactly", async () => {
    const bytes = encodeFcorV1(
      vector.requestKind,
      vector.resources.map((resource) => ({
        kind: resource.kind as "daemon_global",
        value: Uint8Array.from(Buffer.from(resource.valueHex, "hex")),
      })),
      Uint8Array.from(Buffer.from(vector.paramsHex, "hex")),
    );
    expect(Buffer.from(bytes).toString("hex")).toBe(vector.canonicalHex);
    expect(Buffer.from(await hashFcorV1(bytes)).toString("hex")).toBe(vector.sha256Hex);
    expect(validateFcorV1(bytes)).toBe(bytes);
    expect(() => encodeFcorV1("DaemonStatus", [], new Uint8Array())).toThrow();
    expect(() =>
      encodeFcorV1(
        "daemon_status",
        [{ kind: "unknown", value: new Uint8Array() }],
        new Uint8Array(),
      ),
    ).toThrow();
    const oversized = { length: 0x1_0000_0000 } as Uint8Array;
    expect(() =>
      encodeFcorV1("status", [{ kind: "project_id", value: oversized }], new Uint8Array()),
    ).toThrow();
    for (const malformed of vector.malformed) {
      let candidate = Uint8Array.from(bytes);
      if ("replaceByte" in malformed)
        candidate[malformed.replaceByte[0]] = malformed.replaceByte[1];
      if ("truncateBy" in malformed) candidate = candidate.subarray(0, -malformed.truncateBy);
      if ("appendHex" in malformed)
        candidate = Uint8Array.from([...candidate, ...Buffer.from(malformed.appendHex, "hex")]);
      expect(() => validateFcorV1(candidate), malformed.name).toThrow();
    }
    const rich = vector.richPositive;
    const richBytes = encodeFcorV1(
      rich.requestKind,
      rich.resources.map((resource) => ({
        kind: resource.kind,
        value: Uint8Array.from(Buffer.from(resource.valueHex, "hex")),
      })),
      Uint8Array.from(Buffer.from(rich.paramsHex, "hex")),
    );
    expect(Buffer.from(richBytes).toString("hex")).toBe(rich.canonicalHex);
    expect(Buffer.from(await hashFcorV1(richBytes)).toString("hex")).toBe(rich.sha256Hex);
    for (const boundary of vector.sizeCases) {
      const call = () =>
        checkedFcorV1Size(boundary.kindLength, boundary.resourceLengths, boundary.paramsLength);
      if (boundary.valid) expect(call(), boundary.name).toBeGreaterThan(0);
      else expect(call, boundary.name).toThrow();
    }
    for (const shape of vector.shapeCases) {
      const call = () =>
        encodeFcorV1(
          "status",
          [{ kind: shape.kind, value: new Uint8Array(shape.valueLength) }],
          new Uint8Array(),
        );
      if (shape.valid) expect(call(), shape.name).toBeInstanceOf(Uint8Array);
      else expect(call, shape.name).toThrow();
    }
    const primitive = new CanonicalParamsV1();
    primitive.pushU8(0xff);
    primitive.pushBool(true);
    primitive.pushU16(0x1234);
    primitive.pushU32(0x01020304);
    primitive.pushU64(0x0102030405060708n);
    primitive.pushI64(-2n);
    primitive.pushUuid(Uint8Array.from({ length: 16 }, (_, index) => index));
    expect(Buffer.from(primitive.finish()).toString("hex")).toBe(
      vector.canonicalParams.primitiveHex,
    );
    const map = new CanonicalParamsV1();
    map.pushStringMap([
      ["b", "y"],
      ["a", "x"],
    ]);
    expect(Buffer.from(map.finish()).toString("hex")).toBe(
      vector.canonicalParams.sortedStringMapHex,
    );
    expect(() => new CanonicalParamsV1().pushString("e\u0301")).toThrow();
    expect(() => new CanonicalParamsV1().pushString("nul\0value")).toThrow();
    expect(() => new CanonicalParamsV1().pushString("\ud800")).toThrow();
    const boundary = (encode: (params: CanonicalParamsV1) => void) => {
      const params = new CanonicalParamsV1();
      encode(params);
      return Buffer.from(params.finish()).toString("hex");
    };
    expect(boundary((params) => params.pushU64((1n << 64n) - 1n))).toBe(
      vector.canonicalParams.u64MaxHex,
    );
    expect(() => boundary((params) => params.pushU64(1n << 64n))).toThrow();
    expect(boundary((params) => params.pushI64(-(1n << 63n)))).toBe(
      vector.canonicalParams.i64MinHex,
    );
    expect(boundary((params) => params.pushI64((1n << 63n) - 1n))).toBe(
      vector.canonicalParams.i64MaxHex,
    );
    expect(() => boundary((params) => params.pushI64(-(1n << 63n) - 1n))).toThrow();
    expect(() => boundary((params) => params.pushI64(1n << 63n))).toThrow();
    expect(boundary((params) => params.pushOptional(undefined, () => {}))).toBe(
      vector.canonicalParams.optionNoneHex,
    );
    expect(
      boundary((params) => params.pushOptional(0x1234, (nested, value) => nested.pushU16(value))),
    ).toBe(vector.canonicalParams.optionSomeU16Hex);
    expect(boundary((params) => params.pushBytes(new Uint8Array()))).toBe(
      vector.canonicalParams.emptyBytesHex,
    );
    expect(boundary((params) => params.pushString("é"))).toBe(
      vector.canonicalParams.composedStringHex,
    );
    expect(
      boundary((params) =>
        params.pushStringMap([
          ["aa", "y"],
          ["b", "x"],
        ]),
      ),
    ).toBe(vector.canonicalParams.encodedLengthSortedMapHex);
    expect(() =>
      boundary((params) =>
        params.pushStringMap([
          ["é", "x"],
          ["e\u0301", "y"],
        ]),
      ),
    ).toThrow();
    const rollback = new CanonicalParamsV1();
    expect(() =>
      rollback.pushOptional("x", (nested) => {
        nested.pushU8(7);
        throw new Error("fail");
      }),
    ).toThrow();
    expect(rollback.finish()).toEqual(new Uint8Array());
    const opaque = new TextEncoder().encode("FCM2foundation-owned");
    let decoded: Uint8Array | undefined;
    validateRegisteredSendUserMessageV2(opaque, (bytes) => {
      decoded = bytes;
    });
    expect(decoded).toBe(opaque);
    expect(() =>
      validateRegisteredSendUserMessageV2(new TextEncoder().encode("BAD!"), () => {}),
    ).toThrow();
    const opaqueFcor = encodeFcorV1("send_user_message", [], opaque);
    expect(opaqueFcor.subarray(-opaque.length)).toEqual(opaque);
  });
});
