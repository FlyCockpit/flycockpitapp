import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  remoteReplayAckResponseV2Schema,
  remoteReplayAckV2Schema,
  remoteReplayRequestV2Schema,
  remoteReplayResponseV2Schema,
} from "./index";

const fixture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../fixtures/remote-operation-replay-v2.json", import.meta.url)),
    "utf8",
  ),
);

describe("remote operation replay v2", () => {
  it("accepts the shared exact request, response, and ack", () => {
    expect(remoteReplayRequestV2Schema.parse(fixture.request)).toEqual(fixture.request);
    expect(remoteReplayResponseV2Schema.parse(fixture.response)).toEqual(fixture.response);
    expect(remoteReplayAckV2Schema.parse(fixture.ack)).toEqual(fixture.ack);
    expect(remoteReplayAckResponseV2Schema.parse(fixture.ackResponse)).toEqual(fixture.ackResponse);
  });
  it("rejects cursor, limit, and attachment spoof vectors", () => {
    for (const value of fixture.invalidRequests) {
      expect(remoteReplayRequestV2Schema.safeParse(value).success).toBe(false);
    }
  });
});
