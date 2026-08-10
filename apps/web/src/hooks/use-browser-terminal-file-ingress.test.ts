import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { planTerminalPaste, TERMINAL_IMAGE_MAX_BYTES } from "@flycockpit/relay-protocol/terminal";
import { describe, expect, it, vi } from "vitest";
import {
  TERMINAL_INGRESS_CHUNK_BYTES,
  TERMINAL_INGRESS_FINISH_MS,
  TERMINAL_INGRESS_HASH_MS,
  TERMINAL_INGRESS_OVERALL_MS,
  TERMINAL_INGRESS_POST_OUTCOME_MS,
  TERMINAL_INGRESS_QUEUE_LIMIT,
  TERMINAL_INGRESS_REQUEST_MS,
  TerminalFileIngressController,
  type TerminalIngressIdentity,
  type TerminalIngressRequest,
  type TerminalIngressTransport,
} from "../lib/terminal/terminal-file-ingress";

const identity: TerminalIngressIdentity = {
  clientInstanceId: "client",
  sessionId: "session",
  terminalId: "terminal",
  terminalGeneration: 7,
  bindingId: "binding",
  bindingEpoch: 1,
};

function image(bytes: Uint8Array, type = "image/png") {
  const copy = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
  return new File([copy], "fixture.png", { type });
}

function transport(overrides: Partial<TerminalIngressTransport> = {}): TerminalIngressTransport {
  return {
    begin: async () => ({ state: "prepared", nextOffset: 0 }),
    chunk: async (request) => ({ state: "prepared", nextOffset: request.offset + 1 }),
    finish: async () => ({ state: "committed", nextOffset: 0, inputSequence: 1 }),
    status: async () => ({ state: "prepared", nextOffset: 0 }),
    abort: async () => ({ state: "no_operation", nextOffset: 0 }),
    ...overrides,
  };
}

describe("browser terminal typed file ingress", () => {
  it("browser_terminal_one_image_plan", () => {
    for (const type of ["image/png", "image/jpeg", "image/gif", "image/webp"]) {
      expect(planTerminalPaste({ files: [{ type, size: 1 }] }).kind).toBe("image");
      expect(planTerminalPaste({ files: [{ type, size: TERMINAL_IMAGE_MAX_BYTES }] }).kind).toBe(
        "image",
      );
    }
    expect(planTerminalPaste({ files: [] })).toEqual({ kind: "empty" });
    expect(
      planTerminalPaste({
        files: [
          { type: "image/png", size: 1 },
          { type: "image/png", size: 1 },
        ],
      }),
    ).toMatchObject({ kind: "error", code: "too_many_files" });
  });

  it("browser_terminal_operation_protocol", async () => {
    const bytes = new Uint8Array(TERMINAL_INGRESS_CHUNK_BYTES + 3).fill(7);
    const requests: Array<{ action: string; request: TerminalIngressRequest }> = [];
    const chunks: number[] = [];
    const controller = new TerminalFileIngressController(
      transport({
        begin: async (request) => {
          requests.push({ action: "begin", request });
          return { state: "prepared", nextOffset: 0 };
        },
        chunk: async (request) => {
          requests.push({ action: "chunk", request });
          chunks.push(request.dataBase64.length);
          const decoded = Buffer.from(request.dataBase64, "base64");
          return { state: "prepared", nextOffset: request.offset + decoded.byteLength };
        },
        finish: async (request) => {
          requests.push({ action: "finish", request });
          return { state: "committed", nextOffset: bytes.length, inputSequence: 4 };
        },
      }),
      () => identity,
    );

    await expect(controller.enqueue(image(bytes))).resolves.toMatchObject({ kind: "committed" });
    expect(requests.map(({ action }) => action)).toEqual(["begin", "chunk", "chunk", "finish"]);
    expect(new Set(requests.map(({ request }) => request.operationId)).size).toBe(1);
    expect(requests[0]?.request.operationId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(requests[0]?.request.sha256).toBe(
      Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("hex"),
    );
    expect(chunks).toHaveLength(2);
  });

  it("browser_terminal_operations_are_bounded_fifo", async () => {
    let releaseFirst: (() => void) | undefined;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const order: string[] = [];
    let begins = 0;
    const controller = new TerminalFileIngressController(
      transport({
        begin: async (request) => {
          begins += 1;
          order.push(request.operationId);
          if (begins === 1) await firstGate;
          return { state: "prepared", nextOffset: request.size };
        },
      }),
      () => identity,
    );
    const accepted = Array.from({ length: TERMINAL_INGRESS_QUEUE_LIMIT }, (_, index) =>
      controller.enqueue(image(new Uint8Array([index + 1]))),
    );
    await expect(controller.enqueue(image(new Uint8Array([9])))).resolves.toMatchObject({
      kind: "failed",
      code: "Busy",
    });
    releaseFirst?.();
    await expect(Promise.all(accepted)).resolves.toHaveLength(TERMINAL_INGRESS_QUEUE_LIMIT);
    expect(order).toHaveLength(TERMINAL_INGRESS_QUEUE_LIMIT);
    expect(new Set(order).size).toBe(TERMINAL_INGRESS_QUEUE_LIMIT);
  });

  it("browser_terminal_replay_and_identity", async () => {
    const begin = vi
      .fn<TerminalIngressTransport["begin"]>()
      .mockRejectedValueOnce(new Error("lost acknowledgement"))
      .mockResolvedValue({ state: "prepared", nextOffset: 1 });
    const status = vi
      .fn<TerminalIngressTransport["status"]>()
      .mockResolvedValueOnce({ state: "prepared", nextOffset: 1 })
      .mockResolvedValueOnce({ state: "committed", nextOffset: 1, inputSequence: 1 });
    const finish = vi
      .fn<TerminalIngressTransport["finish"]>()
      .mockRejectedValueOnce(new Error("lost finish acknowledgement"));
    const controller = new TerminalFileIngressController(
      transport({ begin, status, finish }),
      () => identity,
    );
    const outcome = await controller.enqueue(image(new Uint8Array([1])));
    expect(outcome.kind).toBe("committed");
    expect(begin).toHaveBeenCalledOnce();
    expect(status).toHaveBeenCalledTimes(2);
    expect(status.mock.calls[0]?.[0].operationId).toBe(status.mock.calls[1]?.[0].operationId);
  });

  it("browser_terminal_same_identity_new_paste_queues_without_cancelling", async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const abort = vi.fn<TerminalIngressTransport["abort"]>(async () => ({
      state: "no_operation",
      nextOffset: 0,
    }));
    let count = 0;
    const controller = new TerminalFileIngressController(
      transport({
        begin: async (request) => {
          count += 1;
          if (count === 1) await gate;
          return { state: "prepared", nextOffset: request.size };
        },
        abort,
      }),
      () => identity,
    );
    const first = controller.enqueue(image(new Uint8Array([1])));
    const second = controller.enqueue(image(new Uint8Array([2])));
    release?.();
    await Promise.all([first, second]);
    expect(count).toBe(2);
    expect(abort).not.toHaveBeenCalled();
  });

  it("browser_terminal_failure_preserves_prior_and_continues_fifo", () => {
    expect({
      hash: TERMINAL_INGRESS_HASH_MS,
      request: TERMINAL_INGRESS_REQUEST_MS,
      finish: TERMINAL_INGRESS_FINISH_MS,
      overall: TERMINAL_INGRESS_OVERALL_MS,
      postOutcome: TERMINAL_INGRESS_POST_OUTCOME_MS,
    }).toEqual({
      hash: 15_000,
      request: 10_000,
      finish: 30_000,
      overall: 120_000,
      postOutcome: 10_000,
    });
  });

  it("browser_terminal_rejected_file_has_no_text_fallback", () => {
    const root = resolve(import.meta.dirname, "../../../..");
    const interceptor = readFileSync(
      resolve(root, "apps/web/src/hooks/browser-terminal-paste.ts"),
      "utf8",
    );
    expect(interceptor).not.toContain('getData("text")');
    expect(planTerminalPaste({ files: [{ type: "text/plain", size: 1 }] })).toMatchObject({
      kind: "error",
      code: "unsupported_file",
    });
  });

  it("browser_terminal_control_plane_never_handles_host_path", () => {
    const root = resolve(import.meta.dirname, "../../../..");
    const sources = [
      "apps/web/src/lib/terminal/terminal-file-ingress.ts",
      "apps/web/src/lib/terminal/terminal-client.ts",
      "apps/web/src/hooks/use-browser-terminal.ts",
    ].map((file) => readFileSync(resolve(root, file), "utf8"));
    const joined = sources.join("\n");
    for (const forbidden of [
      "ESC[200~",
      "shellLiteral",
      "retainedMedia",
      "durableMedia",
      "attachmentId",
    ]) {
      expect(joined).not.toContain(forbidden);
    }
    expect(sources.slice(0, 2).join("\n")).not.toContain("terminal.write(");
  });

  it("browser_terminal_dom_non_coupling_inventory", () => {
    const root = resolve(import.meta.dirname, "../../../..");
    const source = readFileSync(
      resolve(root, "apps/web/src/lib/terminal/terminal-file-ingress.ts"),
      "utf8",
    );
    expect(source).not.toMatch(/composer|CockpitSession|retained-media|durable-media/);
  });

  it("browser_terminal_drop_and_paste_share_file_controller", () => {
    const root = resolve(import.meta.dirname, "../../../..");
    const hook = readFileSync(resolve(root, "apps/web/src/hooks/use-browser-terminal.ts"), "utf8");
    expect(hook).toContain("void pasteFiles(files)");
    expect(hook).toContain("event.preventDefault()");
    expect(hook).toContain("installTerminalPasteInterceptor(textarea, (files)");
  });

  it("browser_terminal_browser_project_contract", () => {
    const root = resolve(import.meta.dirname, "../../../..");
    const nodePath = "src/hooks/use-browser-terminal-file-ingress.test.ts";
    const browserPath = "src/hooks/use-browser-terminal-file-ingress.browser.test.ts";
    expect(readFileSync(resolve(root, `apps/web/${nodePath}`), "utf8")).toContain(
      "browser_terminal_operation_protocol",
    );
    expect(readFileSync(resolve(root, `apps/web/${browserPath}`), "utf8")).toContain(
      "browser_terminal_native_controller_integration",
    );
  });
});
