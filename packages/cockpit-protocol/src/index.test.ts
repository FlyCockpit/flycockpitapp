import { describe, expect, it } from "vitest";
import { z } from "zod";
import errorsFixture from "../fixtures/daemon-wire/errors.json" with { type: "json" };
import eventsFixture from "../fixtures/daemon-wire/events.json" with { type: "json" };
import interruptsFixture from "../fixtures/daemon-wire/interrupts.json" with { type: "json" };
import requestsFixture from "../fixtures/daemon-wire/requests.json" with { type: "json" };
import responsesFixture from "../fixtures/daemon-wire/responses.json" with { type: "json" };
import {
  clientEnvelopeSchema,
  commandDetailSchema,
  errorEnvelopeSchema,
  eventEnvelopeSchema,
  grantKindSchema,
  interruptQuestionSchema,
  knownEventEnvelopeSchema,
  PROTOCOL_VERSION,
  resolveResponseSchema,
  responseEnvelopeSchema,
  sandboxEscalationSchema,
  serverMessageSchema,
} from ".";

const goldenFiles = [
  requestsFixture,
  responsesFixture,
  eventsFixture,
  errorsFixture,
  interruptsFixture,
] as const;
const interruptRaisedDataSchema = z.object({ question: interruptQuestionSchema });

describe("cockpit-proto daemon wire schemas", () => {
  it("parses every golden request envelope", () => {
    for (const [name, frame] of Object.entries(requestsFixture)) {
      const parsed = clientEnvelopeSchema.safeParse(frame);
      expect(parsed.success, name).toBe(true);
      if (parsed.success) expect(parsed.data.request).toBe(name);
    }
  });

  it("parses every golden response envelope", () => {
    for (const [name, frame] of Object.entries(responsesFixture)) {
      const parsed = responseEnvelopeSchema.safeParse(frame);
      expect(parsed.success, name).toBe(true);
      if (parsed.success) expect(parsed.data.response).toBe(name);
    }
    expect(
      responseEnvelopeSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "res",
        id: "11111111-1111-4111-8111-111111111111",
        response: "session_messages",
        data: { messages: [] },
      }).success,
    ).toBe(false);
    expect(
      responseEnvelopeSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "res",
        id: "11111111-1111-4111-8111-111111111111",
        response: "stats_rollup",
        data: { rollup: {} },
      }).success,
    ).toBe(false);
  });

  it("parses every golden event envelope and maps every known kind", () => {
    for (const [name, frame] of Object.entries(eventsFixture)) {
      const known = knownEventEnvelopeSchema.safeParse(frame);
      expect(known.success, name).toBe(true);
      if (known.success) expect(known.data.event).toBe(name);

      const parsed = eventEnvelopeSchema.parse(frame);
      expect("__unknown" in parsed, name).toBe(false);
    }
  });

  it("tolerates and flags an unknown event kind", () => {
    const parsed = eventEnvelopeSchema.parse({
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "future_daemon_event",
      data: { payload: true },
    });
    expect(parsed).toMatchObject({
      event: "future_daemon_event",
      __unknown: true,
    });
  });

  it("rejects malformed known event payloads", () => {
    expect(
      eventEnvelopeSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "evt",
        event: "interrupt_resolved",
        data: {
          session_id: "11111111-1111-4111-8111-111111111111",
          interrupt_id: "22222222-2222-4222-8222-222222222222",
        },
      }).success,
    ).toBe(true);
    expect(
      eventEnvelopeSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "evt",
        event: "interrupt_raised",
        data: {
          session_id: "11111111-1111-4111-8111-111111111111",
          interrupt_id: "22222222-2222-4222-8222-222222222222",
          agent: "builder",
          description: "bad interrupt",
          question: { kind: "single", data: { prompt: "Missing options" } },
        },
      }).success,
    ).toBe(false);
  });

  it("parses every golden err frame into code and message", () => {
    for (const [name, frame] of Object.entries(errorsFixture)) {
      const parsed = errorEnvelopeSchema.safeParse(frame);
      expect(parsed.success, name).toBe(true);
      if (parsed.success) {
        expect(parsed.data.error.code).toEqual(expect.any(String));
        expect(parsed.data.error.message).toEqual(expect.any(String));
      }
    }
    expect(errorEnvelopeSchema.parse(errorsFixture.bad_request_out_of_band).id).toBeUndefined();
  });

  it("parses every interrupt-question and resolve-response variant from the golden", () => {
    const questionKinds = new Set<string>();
    const maskedValues = new Set<boolean>();
    const responseKinds = new Set<string>();

    for (const frame of Object.values(interruptsFixture)) {
      const eventFrame = eventEnvelopeSchema.safeParse(frame);
      const requestFrame = clientEnvelopeSchema.safeParse(frame);
      expect(eventFrame.success || requestFrame.success).toBe(true);
      if (eventFrame.success && eventFrame.data.event === "interrupt_raised") {
        const question = interruptRaisedDataSchema.parse(eventFrame.data.data).question;
        questionKinds.add(question.kind);
        if (question.kind === "freetext") {
          maskedValues.add(question.data.masked ?? false);
        }
      }
      if (requestFrame.success && requestFrame.data.request === "resolve_interrupt") {
        const response = resolveResponseSchema.parse(requestFrame.data.params.response);
        responseKinds.add(response.kind);
        if (response.kind === "batch") {
          expect(response.data.responses.some((child) => child.kind !== "batch")).toBe(true);
        }
      }
    }

    expect(questionKinds).toEqual(new Set(["single", "multi", "freetext"]));
    expect(maskedValues).toEqual(new Set([true, false]));
    expect(responseKinds).toEqual(new Set(["single", "multi", "freetext", "batch", "cancel"]));
  });

  it("parses command_detail present and absent, sandbox_escalation, and all grant kinds", () => {
    const present = interruptsFixture.event_single_command_detail_present.data.question.data;
    expect(commandDetailSchema.safeParse(present.command_detail).success).toBe(true);
    expect(
      "command_detail" in interruptsFixture.event_single_command_detail_absent.data.question.data,
    ).toBe(false);

    expect(sandboxEscalationSchema.safeParse(present.sandbox_escalation).success).toBe(true);
    expect(
      sandboxEscalationSchema.parse(
        interruptsFixture.event_single_sandbox_denial_absent.data.question.data.sandbox_escalation,
      ).denial,
    ).toBeUndefined();

    const grantKinds = new Set(
      [
        interruptsFixture.event_single_grant_command,
        interruptsFixture.event_single_grant_path,
        interruptsFixture.event_single_grant_mcp_tool,
      ].map((frame) => grantKindSchema.parse(frame.data.question.data.approval_class)),
    );
    expect(grantKinds).toEqual(new Set(["command", "path", "mcp_tool"]));
  });

  it("asserts every golden envelope v equals PROTOCOL_VERSION", () => {
    for (const file of goldenFiles) {
      for (const [name, frame] of Object.entries(file)) {
        expect(frame.v, name).toBe(PROTOCOL_VERSION);
      }
    }
  });

  it("rejects the legacy type/ok/result server shape", () => {
    expect(serverMessageSchema.safeParse({ type: "response", id: "req-1", ok: true }).success).toBe(
      false,
    );
  });
});
