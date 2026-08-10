import { describe, expect, it } from "vitest";
import vectors from "../fixtures/client-actor-binding-v1.json" with { type: "json" };
import { clientActorBindingSchema } from "./envelopes";

describe("client actor binding v1", () => {
  it("preserves the full u64 range as canonical decimal text", () => {
    for (const vector of vectors.valid) {
      expect(clientActorBindingSchema.parse(vector.value), vector.name).toEqual(vector.value);
    }
  });

  it("rejects every malformed shared vector", () => {
    for (const vector of vectors.invalid) {
      expect(clientActorBindingSchema.safeParse(vector.value).success, vector.name).toBe(false);
    }
  });
});
