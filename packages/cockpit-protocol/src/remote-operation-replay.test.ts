import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  remoteReplayAckResponseSchema,
  remoteReplayAckSchema,
  remoteReplayRequestSchema,
  remoteReplayResponseSchema,
} from "./index";

const fixture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../fixtures/remote-operation-replay.json", import.meta.url)),
    "utf8",
  ),
);

describe("remote operation replay v2", () => {
  it("accepts the shared exact request, response, and ack", () => {
    expect(remoteReplayRequestSchema.parse(fixture.request)).toEqual(fixture.request);
    expect(remoteReplayResponseSchema.parse(fixture.response)).toEqual(fixture.response);
    expect(remoteReplayAckSchema.parse(fixture.ack)).toEqual(fixture.ack);
    expect(remoteReplayAckResponseSchema.parse(fixture.ackResponse)).toEqual(fixture.ackResponse);
  });
  it("rejects cursor, limit, and attachment spoof vectors", () => {
    for (const value of fixture.invalidRequests) {
      expect(remoteReplayRequestSchema.safeParse(value).success).toBe(false);
    }
  });
});
