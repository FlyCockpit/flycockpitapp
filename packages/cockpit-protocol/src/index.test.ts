import { describe, expect, it } from "vitest";
import { z } from "zod";
import errorsFixture from "../fixtures/daemon-wire/errors.json" with { type: "json" };
import eventsFixture from "../fixtures/daemon-wire/events.json" with { type: "json" };
import interruptsFixture from "../fixtures/daemon-wire/interrupts.json" with { type: "json" };
import requestsFixture from "../fixtures/daemon-wire/requests.json" with { type: "json" };
import responsesFixture from "../fixtures/daemon-wire/responses.json" with { type: "json" };
import {
  activeModelStateSchema,
  clientEnvelopeSchema,
  commandDetailSchema,
  defaultModelUpdateOutcomeSchema,
  errorEnvelopeSchema,
  eventEnvelopeSchema,
  grantKindSchema,
  interruptQuestionSchema,
  knownEventEnvelopeSchema,
  modelSelectionOutcomeSchema,
  modelSelectionResultDataSchema,
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

  it("requires set_default_model to carry either a reference or clear", () => {
    const base = {
      v: PROTOCOL_VERSION,
      kind: "req" as const,
      id: "11111111-1111-4111-8111-111111111111",
      request: "set_default_model" as const,
    };
    const id = "22222222-2222-4222-8222-222222222222";
    expect(
      clientEnvelopeSchema.safeParse({
        ...base,
        params: { default_update_id: id, provider: "openai", model: "gpt-5" },
      }).success,
    ).toBe(true);
    expect(
      clientEnvelopeSchema.safeParse({ ...base, params: { default_update_id: id, clear: true } })
        .success,
    ).toBe(true);
    // A clear must not carry a reference, and a set must not omit one.
    expect(
      clientEnvelopeSchema.safeParse({
        ...base,
        params: { default_update_id: id, clear: true, provider: "openai", model: "gpt-5" },
      }).success,
    ).toBe(false);
    expect(
      clientEnvelopeSchema.safeParse({ ...base, params: { default_update_id: id } }).success,
    ).toBe(false);
    // Empty strings are not a stand-in for absence.
    expect(
      clientEnvelopeSchema.safeParse({
        ...base,
        params: { default_update_id: id, provider: "", model: "" },
      }).success,
    ).toBe(false);
  });

  it("accepts only verified default-model outcomes", () => {
    const verified = {
      status: "verified",
      selection: { provider: "openai", model: "gpt-5" },
      generation: 3,
      scope_label: "user",
      unchanged: false,
    };
    expect(defaultModelUpdateOutcomeSchema.safeParse(verified).success).toBe(true);
    expect(defaultModelUpdateOutcomeSchema.safeParse({ status: "not_requested" }).success).toBe(
      true,
    );
    // The retired shapes claimed a write without proving the effective result.
    expect(defaultModelUpdateOutcomeSchema.safeParse({ status: "saved" }).success).toBe(false);
    expect(
      defaultModelUpdateOutcomeSchema.safeParse({
        status: "failed",
        user_message: "nope",
        diagnostic_code: "x",
      }).success,
    ).toBe(false);
    // A verified outcome without its proof metadata is not acceptable either.
    expect(
      defaultModelUpdateOutcomeSchema.safeParse({ status: "verified", scope_label: "user" })
        .success,
    ).toBe(false);
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
    expect(
      eventEnvelopeSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "evt",
        event: "session_persist_failed",
        data: {
          session_id: "11111111-1111-4111-8111-111111111111",
          error: "missing exact submission identity",
        },
      }).success,
    ).toBe(false);
    const folded = eventsFixture.queued_user_messages_folded;
    expect(
      eventEnvelopeSchema.safeParse({
        ...folded,
        data: { ...folded.data, queue_item_ids: ["not-a-uuid"] },
      }).success,
    ).toBe(false);
    expect(
      eventEnvelopeSchema.safeParse({
        ...folded,
        data: { ...folded.data, target: { ...folded.data.target, depth: -1 } },
      }).success,
    ).toBe(false);
    const { text: _text, ...foldedWithoutText } = folded.data;
    expect(eventEnvelopeSchema.safeParse({ ...folded, data: foldedWithoutText }).success).toBe(
      false,
    );
  });

  it("locks the v6 nested active-model shape and terminal outcome variants", () => {
    expect(
      eventEnvelopeSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "evt",
        event: "active_model_state",
        data: {
          session_id: "11111111-1111-4111-8111-111111111111",
          provider: "openai",
          model: "removed-v5-shape",
          diverged: false,
          generation: 1,
        },
      }).success,
    ).toBe(false);

    const activeState = {
      selection: {
        provider: "openai",
        model: "gpt-5",
        reasoning_effort: { value: "high" },
        thinking_mode: "high",
        prompt_cache_retention: "extended",
      },
      default_selection: {
        provider: "openai",
        model: "gpt-5",
        reasoning_effort: { value: "high" },
        thinking_mode: "high",
        prompt_cache_retention: "extended",
      },
      diverged: false,
      generation: 3,
    } as const;
    const { generation: _generation, ...missingGeneration } = activeState;
    expect(activeModelStateSchema.safeParse(missingGeneration).success).toBe(false);
    const outcomes = [
      {
        status: "applied",
        active_state: activeState,
        default_update: { status: "not_requested" },
      },
      {
        status: "applied",
        active_state: activeState,
        default_update: {
          status: "verified",
          selection: activeState.selection,
          generation: 3,
          scope_label: "user",
          unchanged: false,
        },
      },
      {
        status: "rejected",
        user_message: "The model could not be built.",
        diagnostic_code: "model_selection_build_failed",
      },
    ];
    for (const outcome of outcomes) {
      expect(modelSelectionOutcomeSchema.safeParse(outcome).success).toBe(true);
    }

    expect(
      modelSelectionResultDataSchema.safeParse({
        session_id: "11111111-1111-4111-8111-111111111111",
        selection_id: "22222222-2222-4222-8222-222222222222",
        provider: "openai",
        model: "gpt-5",
        reasoning_effort: "high",
        thinking_mode: "turbo",
        prompt_cache_retention: "extended",
        outcome: outcomes[2],
      }).success,
    ).toBe(false);

    expect(
      clientEnvelopeSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "req",
        id: "22222222-2222-4222-8222-222222222222",
        request: "set_active_model",
        params: {
          selection_id: "11111111-1111-4111-8111-111111111111",
          provider: "openai",
          model: "gpt-5",
          reasoning_effort: "",
          persist_as_default: false,
        },
      }).success,
    ).toBe(false);

    // Plain Enter is session-only, so there is no "initialize if missing"
    // companion flag to be ambiguous with; an unknown key is rejected outright.
    expect(
      clientEnvelopeSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "req",
        id: "22222222-2222-4222-8222-222222222222",
        request: "set_active_model",
        params: {
          selection_id: "11111111-1111-4111-8111-111111111111",
          provider: "openai",
          model: "gpt-5",
          persist_as_default: true,
          initialize_default_if_missing: true,
        },
      }).success,
    ).toBe(false);

    expect(
      clientEnvelopeSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "req",
        id: "22222222-2222-4222-8222-222222222222",
        request: "send_user_message",
        params: {
          client_submission_id: "00000000-0000-0000-0000-000000000000",
          text: "hello",
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
