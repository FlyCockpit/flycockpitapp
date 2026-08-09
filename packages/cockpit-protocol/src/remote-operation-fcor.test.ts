import { describe, expect, it } from "vitest";
import vector from "../fixtures/remote-operation-fcor-v1.json" with { type: "json" };
import { encodeFcorV1 } from "./remote-operation-fcor";

describe("FCOR v1", () => {
  it("matches the shared canonical vector exactly", () => {
    const bytes = encodeFcorV1(
      vector.requestKind,
      vector.resources.map((resource) => ({
        kind: resource.kind as "daemon_global",
        value: Uint8Array.from(Buffer.from(resource.valueHex, "hex")),
      })),
      Uint8Array.from(Buffer.from(vector.paramsHex, "hex")),
    );
    expect(Buffer.from(bytes).toString("hex")).toBe(vector.canonicalHex);
    expect(() => encodeFcorV1("DaemonStatus", [], new Uint8Array())).toThrow();
  });
});
