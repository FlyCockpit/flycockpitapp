import { describe, expect, it } from "vitest";
import { attachResultSchema, createEnvelope, liveEventSchema, serverMessageSchema } from ".";
import attachFixture from "./fixtures/attach.json" with { type: "json" };
import eventsFixture from "./fixtures/events.json" with { type: "json" };

describe("cockpit protocol codecs", () => {
  it("parses attach history fixtures from the daemon JSON shape", () => {
    const parsed = attachResultSchema.parse(attachFixture);
    expect(parsed.session.sessionId).toBe("s1");
    expect(parsed.history.map((entry) => entry.kind)).toEqual([
      "user_message",
      "assistant_text",
      "tool_call",
      "interrupt",
    ]);
    expect(attachResultSchema.parse(JSON.parse(JSON.stringify(parsed)))).toEqual(parsed);
  });

  it("parses live event fixtures and server message envelopes", () => {
    const events = eventsFixture.map((event) => liveEventSchema.parse(event));
    expect(events.map((event) => event.type)).toEqual([
      "history_entry",
      "assistant_delta",
      "usage",
      "interrupt_resolved",
      "idle",
    ]);
    const message = serverMessageSchema.parse({ type: "event", event: events[0] });
    expect(message.type).toBe("event");
  });

  it("round-trips outbound client envelopes", () => {
    const envelope = createEnvelope("req-1", {
      type: "send_user_message",
      sessionId: "s1",
      text: "hello",
      clientMessageId: "client-1",
    });
    expect(createEnvelope(envelope.id, envelope.request)).toEqual(envelope);
  });
});
