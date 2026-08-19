import { describe, expect, it } from "vitest";
import {
  ClipboardWriteRateLimiter,
  planTerminalPaste,
  TERMINAL_IMAGE_MAX_BYTES,
  TERMINAL_INGRESS_ERROR_CODES,
  terminalClientPayloadSchema,
  terminalDaemonPayloadSchema,
  terminalReattachReducer,
  toTerminalIngressErrorCode,
} from "./terminal";

describe("terminal frame codec", () => {
  it("validates client and daemon terminal frames", () => {
    expect(
      terminalClientPayloadSchema.parse({
        type: "terminal.open",
        v: 1,
        cwd: "/repo",
        cols: 120,
        rows: 32,
      }),
    ).toMatchObject({ type: "terminal.open", cwd: "/repo" });

    expect(
      terminalDaemonPayloadSchema.parse({
        type: "terminal.opened",
        v: 1,
        terminalId: "pty-1",
        viewerCount: 1,
        recording: false,
        bindingId: "550e8400-e29b-41d4-a716-446655440000",
        bindingEpoch: 1,
        terminalGeneration: 1,
      }),
    ).toMatchObject({ type: "terminal.opened", terminalId: "pty-1" });

    expect(() =>
      terminalClientPayloadSchema.parse({ type: "terminal.resize", v: 1, cols: 1, rows: 24 }),
    ).toThrow();
  });

  it("terminal_ingress_no_reusable_authority_or_sensitive_control_plane", () => {
    const identity = {
      operationId: "550e8400-e29b-41d4-a716-446655440000",
      bindingId: "550e8400-e29b-41d4-a716-446655440001",
      bindingEpoch: 1,
    };
    expect(() =>
      terminalClientPayloadSchema.parse({
        type: "terminal.ingress_begin",
        v: 1,
        ...identity,
        mediaType: "image/png",
        size: 8,
        sha256: "0".repeat(64),
        name: "browser-name.png",
      }),
    ).toThrow();
    expect(() =>
      terminalDaemonPayloadSchema.parse({
        type: "terminal.ingress_state",
        v: 1,
        operationId: identity.operationId,
        state: "committed",
        nextOffset: 8,
        inputSequence: 1,
        path: "/private/secret.png",
      }),
    ).toThrow();
    expect(
      terminalClientPayloadSchema.parse({ type: "terminal.ingress_abort", v: 1, ...identity }),
    ).toMatchObject({ type: "terminal.ingress_abort", operationId: identity.operationId });
    expect(
      terminalDaemonPayloadSchema.parse({
        type: "terminal.ingress_state",
        v: 1,
        operationId: identity.operationId,
        state: "no_operation",
        nextOffset: 0,
      }),
    ).toMatchObject({ state: "no_operation" });
  });
});

describe("terminal paste router", () => {
  it("plans one structural image without a text route", () => {
    const plan = planTerminalPaste({
      files: [{ name: "screen.png", type: "image/png", size: 123 }],
    });

    expect(plan).toMatchObject({
      kind: "image",
      image: { kind: "image", name: "screen.png" },
    });
  });

  it("returns empty when no file is present", () => {
    expect(planTerminalPaste({})).toEqual({ kind: "empty" });
  });

  it("rejects a multi-file gesture as a whole", () => {
    expect(
      planTerminalPaste({
        files: [
          { name: "one.png", type: "image/png", size: 1 },
          { name: "two.png", type: "image/png", size: 1 },
        ],
      }),
    ).toEqual({
      kind: "error",
      code: "too_many_files",
      maxBytes: TERMINAL_IMAGE_MAX_BYTES,
    });
  });

  it("rejects oversized images before upload", () => {
    expect(
      planTerminalPaste({
        files: [{ name: "huge.png", type: "image/png", size: TERMINAL_IMAGE_MAX_BYTES + 1 }],
      }),
    ).toEqual({
      kind: "error",
      code: "image_too_large",
      maxBytes: TERMINAL_IMAGE_MAX_BYTES,
    });
  });

  it("accepts only the exact terminal image contract and inclusive size bounds", () => {
    for (const type of ["image/png", "image/jpeg", "image/gif", "image/webp"]) {
      expect(planTerminalPaste({ files: [{ type, size: 1 }] }).kind).toBe("image");
      expect(planTerminalPaste({ files: [{ type, size: TERMINAL_IMAGE_MAX_BYTES }] }).kind).toBe(
        "image",
      );
    }
    for (const file of [
      { type: "image/svg+xml", size: 1 },
      { type: "image/png", size: 0 },
    ]) {
      expect(planTerminalPaste({ files: [file] }).kind).toBe("error");
    }
  });
});

describe("terminal ingress error code vocabulary", () => {
  it("exports a single unified snake_case error code set", () => {
    // AC5: one shared error vocabulary. The paste planner codes and the
    // controller PascalCase codes must all map into this set.
    expect(TERMINAL_INGRESS_ERROR_CODES).toContain("too_many_files");
    expect(TERMINAL_INGRESS_ERROR_CODES).toContain("image_too_large");
    expect(TERMINAL_INGRESS_ERROR_CODES).toContain("unsupported_file");
    expect(TERMINAL_INGRESS_ERROR_CODES).toContain("busy");
    expect(TERMINAL_INGRESS_ERROR_CODES).toContain("hash_failed");
    expect(TERMINAL_INGRESS_ERROR_CODES).toContain("deadline_exceeded");
    expect(TERMINAL_INGRESS_ERROR_CODES).toContain("terminal_unavailable");
    expect(TERMINAL_INGRESS_ERROR_CODES).toContain("upload_failed");
  });

  it("maps every PascalCase controller code to the unified snake_case vocabulary", () => {
    // The FIFO ingress controller historically emits PascalCase; each one must
    // map to a canonical snake_case code so the UI locale has one key per code.
    expect(toTerminalIngressErrorCode("TooManyFiles")).toBe("too_many_files");
    expect(toTerminalIngressErrorCode("TooLarge")).toBe("image_too_large");
    expect(toTerminalIngressErrorCode("UnsupportedType")).toBe("unsupported_file");
    expect(toTerminalIngressErrorCode("Busy")).toBe("busy");
    expect(toTerminalIngressErrorCode("HashFailed")).toBe("hash_failed");
    expect(toTerminalIngressErrorCode("Conflict")).toBe("conflict");
    expect(toTerminalIngressErrorCode("UploadFailed")).toBe("upload_failed");
    expect(toTerminalIngressErrorCode("MaterializationFailed")).toBe("materialization_failed");
    expect(toTerminalIngressErrorCode("Expired")).toBe("expired");
    expect(toTerminalIngressErrorCode("DeadlineExceeded")).toBe("deadline_exceeded");
    expect(toTerminalIngressErrorCode("CommitUnknown")).toBe("commit_unknown");
    expect(toTerminalIngressErrorCode("CleanupPending")).toBe("cleanup_pending");
    expect(toTerminalIngressErrorCode("Cancelled")).toBe("cancelled");
    expect(toTerminalIngressErrorCode("TerminalUnavailable")).toBe("terminal_unavailable");
  });

  it("collapses unknown error strings to the fallback code", () => {
    // Fail closed: an unrecognized error string must not leak through as-is;
    // it maps to the canonical fallback.
    expect(toTerminalIngressErrorCode("some-unknown-code")).toBe("upload_failed");
    expect(toTerminalIngressErrorCode("")).toBe("upload_failed");
  });

  it("round-trips canonical snake_case codes without remapping", () => {
    // AC5: an already-canonical snake_case code (e.g. from the paste planner
    // or a wire frame) must pass through toTerminalIngressErrorCode unchanged
    // — not be collapsed to the fallback. Each canonical code round-trips.
    for (const code of TERMINAL_INGRESS_ERROR_CODES) {
      expect(toTerminalIngressErrorCode(code)).toBe(code);
    }
    // Spot-check the specific regression: too_many_files must NOT become
    // upload_failed (the bug when only the PascalCase map was consulted).
    expect(toTerminalIngressErrorCode("too_many_files")).toBe("too_many_files");
    expect(toTerminalIngressErrorCode("image_too_large")).toBe("image_too_large");
    expect(toTerminalIngressErrorCode("deadline_exceeded")).toBe("deadline_exceeded");
  });

  it("paste plan error codes are members of the unified vocabulary", () => {
    // The paste planner's error codes must be from the same set — no dual vocab.
    const tooMany = planTerminalPaste({
      files: [
        { type: "image/png", size: 1 },
        { type: "image/png", size: 1 },
      ],
    });
    expect(tooMany.kind).toBe("error");
    if (tooMany.kind === "error") {
      expect(tooMany.code).toBe("too_many_files");
      expect(TERMINAL_INGRESS_ERROR_CODES).toContain(tooMany.code);
    }
    // Use an input exceeding TERMINAL_IMAGE_MAX_BYTES so the image_too_large
    // error is genuine (a size: 0 file is an edge case, not a representative
    // oversized-image rejection). Assert kind/code before vocabulary membership.
    const tooLarge = planTerminalPaste({
      files: [{ type: "image/png", size: TERMINAL_IMAGE_MAX_BYTES + 1 }],
    });
    expect(tooLarge.kind).toBe("error");
    if (tooLarge.kind === "error") {
      expect(tooLarge.code).toBe("image_too_large");
      expect(TERMINAL_INGRESS_ERROR_CODES).toContain(tooLarge.code);
    }
    const unsupported = planTerminalPaste({ files: [{ type: "text/plain", size: 1 }] });
    expect(unsupported.kind).toBe("error");
    if (unsupported.kind === "error") {
      expect(unsupported.code).toBe("unsupported_file");
      expect(TERMINAL_INGRESS_ERROR_CODES).toContain(unsupported.code);
    }
  });
});

describe("terminal reattach state machine", () => {
  it("moves disconnected open terminals into the reattachable state", () => {
    const open = terminalReattachReducer({ status: "new" }, { type: "opened", terminalId: "t1" });
    expect(open).toEqual({ status: "open", terminalId: "t1" });
    expect(terminalReattachReducer(open, { type: "disconnect" })).toEqual({
      status: "reattachable",
      terminalId: "t1",
    });
  });

  it("falls back to a new terminal when reattach fails", () => {
    expect(
      terminalReattachReducer(
        { status: "reattachable", terminalId: "t1" },
        { type: "reattach_failed" },
      ),
    ).toEqual({ status: "new" });
  });
});

describe("terminal clipboard write limiter", () => {
  it("limits repeated OSC 52 clipboard writes in a time window", () => {
    const limiter = new ClipboardWriteRateLimiter(2, 1000);
    expect(limiter.allow(0)).toBe(true);
    expect(limiter.allow(100)).toBe(true);
    expect(limiter.allow(200)).toBe(false);
    expect(limiter.allow(1200)).toBe(true);
  });
});
