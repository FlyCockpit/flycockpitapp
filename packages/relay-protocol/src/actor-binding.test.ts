import { describe, expect, it } from "vitest";
import { clientActorBindingSchema } from "./envelopes";

const base = {
  schemaVersion: 1 as const,
  deviceId: "00000000-0000-4000-8000-000000000001",
  deviceGeneration: "9007199254740993",
  logicalAttachmentId: "00000000-0000-4000-8000-000000000002",
};

describe("client actor binding v1", () => {
  it("preserves the full u64 range as canonical decimal text", () => {
    expect(clientActorBindingSchema.parse(base)).toEqual(base);
    expect(
      clientActorBindingSchema.parse({ ...base, deviceGeneration: "18446744073709551615" }),
    ).toMatchObject({ deviceGeneration: "18446744073709551615" });
  });

  it.each([
    { ...base, deviceGeneration: 9007199254740993 },
    { ...base, deviceGeneration: "0" },
    { ...base, deviceGeneration: "01" },
    { ...base, deviceGeneration: "18446744073709551616" },
    { ...base, deviceId: "00000000-0000-0000-0000-000000000000" },
    { ...base, deviceId: "00000000-0000-4000-7000-000000000001" },
    { ...base, deviceId: "00000000-0000-4000-8000-00000000000A" },
    { ...base, schemaVersion: 2 },
    { ...base, unknown: true },
  ])("rejects malformed actor binding %#", (value) => {
    expect(clientActorBindingSchema.safeParse(value).success).toBe(false);
  });
});
