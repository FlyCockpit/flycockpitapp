import { describe, expect, it } from "vitest";
import vector from "../fixtures/remote-operation-fcor-v1.json" with { type: "json" };
import { encodeFcorV1, hashFcorV1, validateFcorV1 } from "./remote-operation-fcor";

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
  });
});
