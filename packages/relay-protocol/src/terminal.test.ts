import { describe, expect, it } from "vitest";
import {
  ClipboardWriteRateLimiter,
  planTerminalPaste,
  TERMINAL_IMAGE_MAX_BYTES,
  terminalClientPayloadSchema,
  terminalDaemonPayloadSchema,
  terminalReattachReducer,
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
      }),
    ).toMatchObject({ type: "terminal.opened", terminalId: "pty-1" });

    expect(() =>
      terminalClientPayloadSchema.parse({ type: "terminal.resize", v: 1, cols: 1, rows: 24 }),
    ).toThrow();
  });
});

describe("terminal paste router", () => {
  it("prefers images over text when files are present", () => {
    const plan = planTerminalPaste({
      text: "ignored",
      files: [{ name: "screen.png", type: "image/png", size: 123 }],
    });

    expect(plan).toMatchObject({
      kind: "images",
      images: [{ kind: "image", name: "screen.png" }],
    });
  });

  it("routes plain text when no file is present", () => {
    expect(planTerminalPaste({ text: "hello" })).toEqual({ kind: "text", text: "hello" });
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
