import { describe, expect, it } from "vitest";
import { z } from "zod";
import errorsFixture from "../fixtures/daemon-wire/errors.json" with { type: "json" };
import eventsFixture from "../fixtures/daemon-wire/events.json" with { type: "json" };
import interruptsFixture from "../fixtures/daemon-wire/interrupts.json" with { type: "json" };
import requestsFixture from "../fixtures/daemon-wire/requests.json" with { type: "json" };
import responsesFixture from "../fixtures/daemon-wire/responses.json" with { type: "json" };
import remoteOperationIdentityFixture from "../fixtures/remote-operation-identity-v1.json" with {
  type: "json",
};
import {
  activeModelStateSchema,
  canonicalToolResultContentSchema,
  clientEnvelopeSchema,
  commandDetailSchema,
  defaultModelUpdateOutcomeSchema,
  errorEnvelopeSchema,
  eventEnvelopeSchema,
  grantKindSchema,
  historyEntrySchema,
  interruptQuestionSchema,
  knownEventEnvelopeSchema,
  modelSelectionOutcomeSchema,
  modelSelectionResultDataSchema,
  PROTOCOL_VERSION,
  pausedWorkSummarySchema,
  remoteOperationIdentityV1Schema,
  resolveResponseSchema,
  responseEnvelopeSchema,
  safeMediaMetadataSchema,
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
  it("enforces canonical UUIDv7 remote operation identities", () => {
    const valid = remoteOperationIdentityFixture.valid;
    expect(remoteOperationIdentityV1Schema.safeParse(valid).success).toBe(true);
    for (const malformed of remoteOperationIdentityFixture.invalid) {
      expect(remoteOperationIdentityV1Schema.safeParse(malformed).success).toBe(false);
    }
  });

  it("parses every golden request envelope", () => {
    for (const [name, frame] of Object.entries(requestsFixture)) {
      const parsed = clientEnvelopeSchema.safeParse(frame);
      expect(parsed.success, name).toBe(true);
      if (parsed.success) expect(parsed.data.request).toBe(name);
    }
  });

  it("accepts only opaque 64KiB-through-8MiB bulk user-message references", () => {
    const envelope = (total_length: string, mime_class = "opaque") => ({
      v: PROTOCOL_VERSION,
      kind: "req",
      id: "11111111-1111-4111-8111-111111111111",
      request: "send_user_message_bulk",
      params: {
        client_submission_id: "22222222-2222-4222-8222-222222222222",
        transfer: {
          transfer_id: "AQIDBAUGBwgJCgsMDQ4PEA",
          total_length,
          sha256: "ab".repeat(32),
          mime_class,
        },
      },
    });
    expect(clientEnvelopeSchema.safeParse(envelope("65537")).success).toBe(true);
    expect(clientEnvelopeSchema.safeParse(envelope(String(8 * 1024 * 1024))).success).toBe(true);
    expect(clientEnvelopeSchema.safeParse(envelope("65536")).success).toBe(false);
    expect(clientEnvelopeSchema.safeParse(envelope(String(8 * 1024 * 1024 + 1))).success).toBe(
      false,
    );
    expect(clientEnvelopeSchema.safeParse(envelope("65537", "archive")).success).toBe(false);

    const withDisplayTransfer = {
      ...envelope("5"),
      params: {
        ...envelope("5").params,
        display_transfer: {
          transfer_id: "AgMEBQYHCAkKCwwNDg8QEQ",
          total_length: String(8 * 1024 * 1024),
          sha256: "cd".repeat(32),
          mime_class: "opaque",
        },
      },
    };
    expect(clientEnvelopeSchema.safeParse(withDisplayTransfer).success).toBe(true);
    expect(
      clientEnvelopeSchema.safeParse({
        ...withDisplayTransfer,
        params: { ...withDisplayTransfer.params, display_text: "inline too" },
      }).success,
    ).toBe(false);
    expect(
      clientEnvelopeSchema.safeParse({
        ...envelope("65537"),
        params: { ...envelope("65537").params, display_text: "x".repeat(65_537) },
      }).success,
    ).toBe(false);
    expect(
      clientEnvelopeSchema.safeParse({
        ...withDisplayTransfer,
        params: {
          ...withDisplayTransfer.params,
          display_transfer: {
            ...withDisplayTransfer.params.display_transfer,
            transfer_id: withDisplayTransfer.params.transfer.transfer_id,
          },
        },
      }).success,
    ).toBe(false);
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

  it("rejects malformed host capability snapshots", () => {
    const frame = eventsFixture.host_capabilities_changed;
    const snapshot = frame.data.snapshot;

    expect(
      knownEventEnvelopeSchema.safeParse({
        ...frame,
        data: {
          ...frame.data,
          snapshot: {
            generation: snapshot.generation,
            features: snapshot.features,
            dependencies: snapshot.dependencies,
          },
        },
      }).success,
    ).toBe(false);

    expect(
      knownEventEnvelopeSchema.safeParse({
        ...frame,
        data: {
          ...frame.data,
          snapshot: {
            ...snapshot,
            dependencies: [{ ...snapshot.dependencies[0], state: "not-a-dependency-state" }],
          },
        },
      }).success,
    ).toBe(false);
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

  it("config_refreshed_typescript_mirror_is_v10", () => {
    expect(PROTOCOL_VERSION).toBe(17);
    expect(responseEnvelopeSchema.parse(responsesFixture.config_refreshed)).toEqual(
      responsesFixture.config_refreshed,
    );
    expect(
      responseEnvelopeSchema.safeParse({
        ...responsesFixture.config_refreshed,
        data: { ...responsesFixture.config_refreshed.data, extra: true },
      }).success,
    ).toBe(false);
  });

  it("bounds mirrored Rust u64 and i64 JSON numbers to exact JavaScript integers", () => {
    const markSeen = requestsFixture.mark_app_flag_seen;
    expect(
      clientEnvelopeSchema.safeParse({
        ...markSeen,
        params: { ...markSeen.params, expected_version: Number.MAX_SAFE_INTEGER },
      }).success,
    ).toBe(true);
    for (const expected_version of [-1, Number.MAX_SAFE_INTEGER + 1, 1e100]) {
      expect(
        clientEnvelopeSchema.safeParse({
          ...markSeen,
          params: { ...markSeen.params, expected_version },
        }).success,
      ).toBe(false);
    }

    for (const request of [
      requestsFixture.attach,
      requestsFixture.read_history_page,
      requestsFixture.read_session_messages,
      requestsFixture.read_subagent_history_page,
    ]) {
      const cursor = request.request === "attach" ? "since_seq" : "before_seq";
      for (const value of [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]) {
        expect(
          clientEnvelopeSchema.safeParse({
            ...request,
            params: { ...request.params, [cursor]: value },
          }).success,
        ).toBe(true);
      }
      for (const value of [Number.MIN_SAFE_INTEGER - 1, Number.MAX_SAFE_INTEGER + 1]) {
        expect(
          clientEnvelopeSchema.safeParse({
            ...request,
            params: { ...request.params, [cursor]: value },
          }).success,
        ).toBe(false);
      }
    }

    const disclosures = responsesFixture.startup_disclosures;
    for (const cursor_seq of [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]) {
      expect(
        responseEnvelopeSchema.safeParse({
          ...disclosures,
          data: {
            ...disclosures.data,
            org_sync: { ...disclosures.data.org_sync, cursor_seq },
          },
        }).success,
      ).toBe(true);
    }
    for (const cursor_seq of [Number.MIN_SAFE_INTEGER - 1, Number.MAX_SAFE_INTEGER + 1, 1e100]) {
      expect(
        responseEnvelopeSchema.safeParse({
          ...disclosures,
          data: {
            ...disclosures.data,
            org_sync: { ...disclosures.data.org_sync, cursor_seq },
          },
        }).success,
      ).toBe(false);
    }

    expect(
      responseEnvelopeSchema.safeParse({
        ...responsesFixture.workspace_trust_set,
        data: { config_generation: 1e100 },
      }).success,
    ).toBe(false);
    expect(
      responseEnvelopeSchema.safeParse({
        ...responsesFixture.config_refreshed,
        data: { ...responsesFixture.config_refreshed.data, applied_generation: 1e100 },
      }).success,
    ).toBe(false);

    for (const field of [
      "config_generation",
      "inventory_generation",
      "session_generation",
    ] as const) {
      expect(
        responseEnvelopeSchema.safeParse({
          ...responsesFixture.inventory_bundle,
          data: {
            ...responsesFixture.inventory_bundle.data,
            [field]: Number.MAX_SAFE_INTEGER,
          },
        }).success,
      ).toBe(true);
      expect(
        responseEnvelopeSchema.safeParse({
          ...responsesFixture.inventory_bundle,
          data: {
            ...responsesFixture.inventory_bundle.data,
            [field]: Number.MAX_SAFE_INTEGER + 1,
          },
        }).success,
      ).toBe(false);
    }

    const toolCall = {
      role: "tool_call",
      agent: "Build",
      call_id: "call-1",
      parent_child_index: Number.MIN_SAFE_INTEGER,
      tool: "read",
      original_input: {},
      wire_input: {},
      output: "ok",
      hard_fail: false,
      truncated: false,
    };
    expect(historyEntrySchema.safeParse(toolCall).success).toBe(true);
    expect(
      historyEntrySchema.safeParse({
        ...toolCall,
        parent_child_index: Number.MIN_SAFE_INTEGER - 1,
      }).success,
    ).toBe(false);

    const compactBoundary = {
      role: "compact_boundary",
      predecessor_short_id: "abc123",
      seed_tool_count: 1,
      seed_tool_tokens: Number.MAX_SAFE_INTEGER,
      tokens_before: Number.MAX_SAFE_INTEGER,
      tokens_after: Number.MAX_SAFE_INTEGER,
    };
    expect(historyEntrySchema.safeParse(compactBoundary).success).toBe(true);
    expect(
      historyEntrySchema.safeParse({
        ...compactBoundary,
        seed_tool_tokens: Number.MAX_SAFE_INTEGER + 1,
      }).success,
    ).toBe(false);

    const pausedWork = responsesFixture.attached.data.paused_work[0];
    expect(
      pausedWorkSummarySchema.safeParse({
        ...pausedWork,
        pending_tool_count: Number.MIN_SAFE_INTEGER,
      }).success,
    ).toBe(true);
    expect(
      pausedWorkSummarySchema.safeParse({
        ...pausedWork,
        pending_tool_count: Number.MIN_SAFE_INTEGER - 1,
      }).success,
    ).toBe(false);
  });

  describe("typed media tool-result transport", () => {
    it("round-trips text content", () => {
      const text = { kind: "text", text: "hello world" };
      expect(canonicalToolResultContentSchema.safeParse(text).success).toBe(true);
    });

    it("round-trips json content", () => {
      const json = { kind: "json", value: { key: "value", num: 42 } };
      expect(canonicalToolResultContentSchema.safeParse(json).success).toBe(true);
    });

    it("round-trips media reference content", () => {
      const mediaRef = {
        kind: "media_reference",
        attachmentId: "00000000-0000-7000-8000-000000000001",
        attachmentVersion: 1,
        mediaKind: "image",
        mimeType: "image/png",
        ordinal: 0,
        purpose: "primary",
        checksum: "a".repeat(64),
        byteCount: 1024,
        dimensions: { width: 1920, height: 1080 },
        availability: "ready",
        provenance: { toolName: "screenshot", sourceLabel: "screen" },
      };
      expect(canonicalToolResultContentSchema.safeParse(mediaRef).success).toBe(true);
    });

    it("round-trips media reference with duration", () => {
      const mediaRef = {
        kind: "media_reference",
        attachmentId: "00000000-0000-7000-8000-000000000002",
        attachmentVersion: 1,
        mediaKind: "audio",
        mimeType: "audio/wav",
        ordinal: 1,
        purpose: "primary",
        checksum: "b".repeat(64),
        byteCount: 2048,
        durationMs: { durationMs: 5000 },
        availability: "ready",
        provenance: { toolName: "recorder" },
      };
      expect(canonicalToolResultContentSchema.safeParse(mediaRef).success).toBe(true);
    });

    it("rejects unknown kind variant", () => {
      expect(
        canonicalToolResultContentSchema.safeParse({
          kind: "unknown",
          text: "hello",
        }).success,
      ).toBe(false);
    });

    it("rejects unknown fields in media reference", () => {
      const mediaRef = {
        kind: "media_reference",
        attachmentId: "00000000-0000-7000-8000-000000000001",
        attachmentVersion: 1,
        mediaKind: "image",
        mimeType: "image/png",
        ordinal: 0,
        purpose: "primary",
        checksum: "a".repeat(64),
        byteCount: 1024,
        availability: "ready",
        provenance: { toolName: "screenshot" },
        evilField: "malicious",
      };
      expect(canonicalToolResultContentSchema.safeParse(mediaRef).success).toBe(false);
    });

    it("rejects invalid checksum (non-hex)", () => {
      const mediaRef = {
        kind: "media_reference",
        attachmentId: "00000000-0000-7000-8000-000000000001",
        attachmentVersion: 1,
        mediaKind: "image",
        mimeType: "image/png",
        ordinal: 0,
        purpose: "primary",
        checksum: "XYZ".repeat(22),
        byteCount: 1024,
        availability: "ready",
        provenance: { toolName: "screenshot" },
      };
      expect(canonicalToolResultContentSchema.safeParse(mediaRef).success).toBe(false);
    });

    it("rejects invalid attachment version (zero)", () => {
      const mediaRef = {
        kind: "media_reference",
        attachmentId: "00000000-0000-7000-8000-000000000001",
        attachmentVersion: 0,
        mediaKind: "image",
        mimeType: "image/png",
        ordinal: 0,
        purpose: "primary",
        checksum: "a".repeat(64),
        byteCount: 1024,
        availability: "ready",
        provenance: { toolName: "screenshot" },
      };
      expect(canonicalToolResultContentSchema.safeParse(mediaRef).success).toBe(false);
    });

    it("projects safe metadata without bytes", () => {
      const metadata = {
        attachmentId: "00000000-0000-7000-8000-000000000001",
        mediaKind: "video",
        mimeType: "video/mp4",
        byteCount: 4096,
        ordinal: 3,
        purpose: "primary",
        durationMs: { durationMs: 10000 },
        provenance: { toolName: "capture" },
        artifactHandle: "handle-abc-123",
      };
      const parsed = safeMediaMetadataSchema.safeParse(metadata);
      expect(parsed.success).toBe(true);
      if (parsed.success) {
        const json = JSON.stringify(parsed.data);
        expect(json).not.toContain("bytes");
        expect(json).not.toContain("base64");
      }
    });

    it("rejects unknown media kind", () => {
      const mediaRef = {
        kind: "media_reference",
        attachmentId: "00000000-0000-7000-8000-000000000001",
        attachmentVersion: 1,
        mediaKind: "document",
        mimeType: "application/pdf",
        ordinal: 0,
        purpose: "primary",
        checksum: "a".repeat(64),
        byteCount: 1024,
        availability: "ready",
        provenance: { toolName: "scanner" },
      };
      expect(canonicalToolResultContentSchema.safeParse(mediaRef).success).toBe(false);
    });
  });
});
