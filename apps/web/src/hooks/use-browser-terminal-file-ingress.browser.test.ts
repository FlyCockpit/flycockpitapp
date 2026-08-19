import { planTerminalPaste } from "@flycockpit/relay-protocol/terminal";
import { Terminal } from "@xterm/xterm";
import { createElement } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";
import {
  TerminalFileIngressController,
  type TerminalIngressIdentity,
  type TerminalIngressTransport,
} from "../lib/terminal/terminal-file-ingress";
import {
  createTerminalDropHandler,
  installTerminalPasteInterceptor,
} from "./browser-terminal-paste";

// Mock TerminalClient so useBrowserTerminal can mount without a WebSocket.
// The hook's real handleDrop is exercised end-to-end; only the network
// transport is stubbed. uploadImage is spied to detect map-split regressions.
const uploadImageMock =
  vi.fn<
    (file: File, onProgress?: (sentBytes: number, totalBytes: number) => void) => Promise<void>
  >();
vi.mock("@/lib/terminal/terminal-client", () => ({
  TerminalClient: class {
    on() {
      return () => {};
    }
    connect() {}
    input() {}
    resize() {}
    close() {}
    uploadImage = uploadImageMock;
  },
}));

const identity: TerminalIngressIdentity = {
  clientInstanceId: "client",
  sessionId: "session",
  terminalId: "terminal",
  terminalGeneration: 1,
  bindingId: "binding",
  bindingEpoch: 1,
};

function fakeTransport(): TerminalIngressTransport {
  return {
    begin: async (request) => ({ state: "prepared", nextOffset: request.size }),
    chunk: async (request) => ({ state: "prepared", nextOffset: request.offset + 1 }),
    finish: async () => ({ state: "committed", nextOffset: 0, inputSequence: 1 }),
    status: async () => ({ state: "prepared", nextOffset: 0 }),
    abort: async () => ({ state: "no_operation", nextOffset: 0 }),
  };
}

describe("browser terminal native typed-file integration", () => {
  it("browser_terminal_native_controller_integration", () => {
    const host = document.createElement("div");
    host.style.width = "800px";
    host.style.height = "400px";
    document.body.append(host);
    const terminal = new Terminal();
    terminal.open(host);
    const textarea = terminal.textarea;
    if (!textarea) throw new Error("xterm textarea missing");
    const ingress = vi.fn();
    const remove = installTerminalPasteInterceptor(textarea, ingress);
    const transfer = new DataTransfer();
    const file = new File([new Uint8Array([1, 2, 3])], "native.png", { type: "image/png" });
    transfer.items.add(file);
    transfer.setData("text/plain", "suppressed text");
    const event = new ClipboardEvent("paste", {
      bubbles: true,
      cancelable: true,
      clipboardData: transfer,
    });

    textarea.dispatchEvent(event);

    expect(event.defaultPrevented).toBe(true);
    expect(ingress).toHaveBeenCalledWith([file]);
    remove();
    terminal.dispose();
    host.remove();
  });

  it("renders authorized opaque terminal output without treating it as ingress state", async () => {
    const host = document.createElement("div");
    document.body.append(host);
    const terminal = new Terminal({ cols: 80, rows: 2 });
    terminal.open(host);
    const opaqueOutput = "/private/terminal-ingress/opaque.png";
    await new Promise<void>((resolve) => terminal.write(opaqueOutput, resolve));
    expect(terminal.buffer.active.getLine(0)?.translateToString(true)).toContain(opaqueOutput);
    terminal.dispose();
    host.remove();
  });

  it("browser_terminal_drop_dom_rejects_multi_file_whole_gesture", () => {
    // Behavioral DOM proof: mount a real textarea, attach the REAL production
    // drop handler (createTerminalDropHandler — the exact factory
    // useBrowserTerminal uses), and dispatch a real two-file DragEvent to it.
    // The handler must forward the COMPLETE file array to pasteFiles in ONE
    // call (whole-gesture), producing a single too_many_files plan.
    // A map-split handleDrop (pasteFiles([file]) per file) would invoke
    // pasteFiles twice with one file each, and each single image would be
    // accepted — so this test FAILS if the production path reverts to
    // map-split.
    const textarea = document.createElement("textarea");
    document.body.append(textarea);
    const pasteFiles = vi.fn((files: readonly File[]) => {
      // Mirror the real pasteFiles: planTerminalPaste({ files }) once.
      planTerminalPaste({ files });
    });
    const dropHandler = createTerminalDropHandler(pasteFiles);
    // Adapter so the structural TerminalDropEvent handler attaches to a raw
    // DOM textarea (production uses React onDrop; tests use addEventListener).
    const listener: EventListener = (event) => dropHandler(event as DragEvent);
    textarea.addEventListener("drop", listener);

    const transfer = new DataTransfer();
    const first = new File([new Uint8Array([1])], "drop-1.png", { type: "image/png" });
    const second = new File([new Uint8Array([2])], "drop-2.png", { type: "image/png" });
    transfer.items.add(first);
    transfer.items.add(second);
    const event = new DragEvent("drop", {
      bubbles: true,
      cancelable: true,
      dataTransfer: transfer,
    });

    textarea.dispatchEvent(event);

    // ONE whole-gesture call with the complete two-file array.
    expect(pasteFiles).toHaveBeenCalledOnce();
    expect(pasteFiles.mock.calls[0]?.[0]).toEqual([first, second]);
    // The complete-array plan is a single too_many_files rejection.
    expect(planTerminalPaste({ files: [first, second] })).toMatchObject({
      kind: "error",
      code: "too_many_files",
    });
    // Distinguishing: each file alone is a valid image plan — a map-split
    // handler would accept both individually, so the once-only assertion
    // above is what rejects that regression.
    expect(planTerminalPaste({ files: [first] }).kind).toBe("image");
    expect(planTerminalPaste({ files: [second] }).kind).toBe("image");
    // The real handler prevents the default drop (no host-path text fallback).
    expect(event.defaultPrevented).toBe(true);

    textarea.removeEventListener("drop", listener);
    textarea.remove();
  });

  it("browser_terminal_drop_dom_zero_file_is_no_op", () => {
    // The real production handler is a no-op for a zero-file drop: pasteFiles
    // is never called and the event is not prevented.
    const textarea = document.createElement("textarea");
    document.body.append(textarea);
    const pasteFiles = vi.fn();
    const dropHandler = createTerminalDropHandler(pasteFiles);
    const listener: EventListener = (event) => dropHandler(event as DragEvent);
    textarea.addEventListener("drop", listener);

    const event = new DragEvent("drop", {
      bubbles: true,
      cancelable: true,
      dataTransfer: new DataTransfer(),
    });
    textarea.dispatchEvent(event);

    expect(pasteFiles).not.toHaveBeenCalled();
    expect(event.defaultPrevented).toBe(false);

    textarea.removeEventListener("drop", listener);
    textarea.remove();
  });

  it("browser_terminal_ingress_controller_e2e_with_real_data_transfer", async () => {
    // AC3/AC6: drive TerminalFileIngressController end-to-end with a real
    // DataTransfer/ClipboardEvent and a fake TerminalIngressTransport. This
    // proves the browser project covers the full ingress pipeline under
    // vitest.browser.config.ts. A broken controller (e.g. one that never
    // commits) would fail the committed assertion.
    const transfer = new DataTransfer();
    const bytes = new Uint8Array([10, 20, 30, 40]);
    const file = new File([bytes], "e2e.png", { type: "image/png" });
    transfer.items.add(file);
    const pasteEvent = new ClipboardEvent("paste", {
      bubbles: true,
      cancelable: true,
      clipboardData: transfer,
    });
    expect(pasteEvent.clipboardData).not.toBeNull();
    const files = Array.from(pasteEvent.clipboardData?.files ?? []);
    expect(files).toHaveLength(1);

    const begin = vi.fn<TerminalIngressTransport["begin"]>();
    const finish = vi.fn<TerminalIngressTransport["finish"]>();
    const controller = new TerminalFileIngressController(
      {
        ...fakeTransport(),
        begin: async (request, signal) => {
          begin(request, signal);
          return { state: "prepared", nextOffset: 0 };
        },
        finish: async (request, signal) => {
          finish(request, signal);
          return { state: "committed", nextOffset: 4, inputSequence: 7 };
        },
      },
      () => identity,
    );

    const outcome = await controller.enqueue(files[0] as File);
    expect(outcome.kind).toBe("committed");
    expect(begin).toHaveBeenCalledOnce();
    expect(finish).toHaveBeenCalledOnce();
    if (outcome.kind === "committed") {
      expect(outcome.inputSequence).toBe(7);
      expect(outcome.operationId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
    }
  });

  it("browser_terminal_ingress_controller_rejects_non_image_from_data_transfer", async () => {
    // A text file from a real DataTransfer must be rejected by the controller
    // before any transport call — proving the browser project covers the
    // type-guard boundary.
    const transfer = new DataTransfer();
    const file = new File([new Uint8Array([1])], "notes.txt", { type: "text/plain" });
    transfer.items.add(file);
    const files = Array.from(transfer.files);
    expect(files).toHaveLength(1);

    const begin = vi.fn<TerminalIngressTransport["begin"]>();
    const controller = new TerminalFileIngressController(
      { ...fakeTransport(), begin },
      () => identity,
    );

    const outcome = await controller.enqueue(files[0] as File);
    expect(outcome.kind).toBe("failed");
    expect(begin).not.toHaveBeenCalled();
  });

  it("browser_terminal_hook_handleDrop_whole_gesture_not_map_split", async () => {
    // Integration test: mount the REAL useBrowserTerminal hook (with a mocked
    // TerminalClient so no WebSocket is opened), grab the ACTUAL returned
    // handleDrop, and dispatch a real two-file DragEvent to it. The hook's
    // handleDrop must forward the COMPLETE file array to pasteFiles in ONE
    // call (whole-gesture), producing a single too_many_files error.
    //
    // A map-split regression (handleDrop reverting to
    // files.forEach(file => void pasteFiles([file])) while keeping the
    // createTerminalDropHandler import) would call pasteFiles twice with one
    // file each; each single image is ACCEPTED by planTerminalPaste, so
    // uploadImage would be called twice and onError would NOT receive
    // "too_many_files". This test FAILS under that regression.
    //
    // We import the hook AFTER vi.mock is registered so the mocked
    // TerminalClient is used.
    const { useBrowserTerminal } = await import("./use-browser-terminal");

    uploadImageMock.mockReset();
    const onError = vi.fn<(code: string) => void>();

    // Capture the hook's returned handleDrop without JSX: a component that
    // stores the terminal state on a mutable handle and renders the
    // container div the hook needs.
    const captured: {
      handleDrop:
        | ((event: { dataTransfer: DataTransfer | null; preventDefault(): void }) => void)
        | null;
    } = {
      handleDrop: null,
    };
    const host = document.createElement("div");
    document.body.append(host);
    const root = createRoot(host);

    function Probe() {
      const state = useBrowserTerminal({
        tokenInfo: {
          token: "t",
          relayUrl: "wss://relay.invalid/t",
          expiresAt: "2099-01-01T00:00:00Z",
        },
        instanceId: "inst",
        instanceName: "name",
        onError,
      });
      captured.handleDrop = state.handleDrop;
      return createElement("div", { ref: state.containerRef });
    }

    await new Promise<void>((resolve) => {
      root.render(createElement(Probe, {}, null));
      // Wait for the hook's useEffect to run (terminal + client init).
      setTimeout(resolve, 50);
    });

    // The hook must have returned a handleDrop function.
    expect(typeof captured.handleDrop).toBe("function");

    // Build a real two-file DragEvent (browser environment provides
    // DataTransfer + DragEvent natively).
    const transfer = new DataTransfer();
    const first = new File([new Uint8Array([1])], "drop-a.png", { type: "image/png" });
    const second = new File([new Uint8Array([2])], "drop-b.png", { type: "image/png" });
    transfer.items.add(first);
    transfer.items.add(second);
    const event = new DragEvent("drop", {
      bubbles: true,
      cancelable: true,
      dataTransfer: transfer,
    });

    // Dispatch through the hook's ACTUAL handleDrop.
    captured.handleDrop!(event);

    // Give the async pasteFiles microtasks a chance to run.
    await new Promise<void>((resolve) => setTimeout(resolve, 20));

    // Whole-gesture: the complete two-file array is rejected as
    // too_many_files, so onError is called ONCE with "too_many_files" and
    // uploadImage is NEVER called (the plan never reaches the image branch).
    expect(onError).toHaveBeenCalledOnce();
    expect(onError.mock.calls[0]?.[0]).toBe("too_many_files");
    expect(uploadImageMock).not.toHaveBeenCalled();

    // Distinguishing proof: each file alone is a valid image plan. A
    // map-split handler would accept both individually, calling uploadImage
    // twice and never emitting too_many_files — so the two assertions above
    // are what reject that regression.
    expect(planTerminalPaste({ files: [first] }).kind).toBe("image");
    expect(planTerminalPaste({ files: [second] }).kind).toBe("image");

    // The real handler prevents the default drop.
    expect(event.defaultPrevented).toBe(true);

    root.unmount();
    host.remove();
  });
});
