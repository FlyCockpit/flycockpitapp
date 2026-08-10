import { Terminal } from "@xterm/xterm";
import { describe, expect, it, vi } from "vitest";
import { installTerminalPasteInterceptor } from "./browser-terminal-paste";

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
});
