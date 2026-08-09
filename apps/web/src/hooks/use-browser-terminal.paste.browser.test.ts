import { Terminal } from "@xterm/xterm";
import { describe, expect, it, vi } from "vitest";
import { installTerminalPasteInterceptor, orderedClipboardFiles } from "./browser-terminal-paste";

function openTerminal() {
  const host = document.createElement("div");
  host.style.width = "800px";
  host.style.height = "400px";
  document.body.append(host);
  const terminal = new Terminal();
  terminal.open(host);
  const textarea = terminal.textarea;
  if (!textarea) throw new Error("xterm did not create its textarea");
  return {
    terminal,
    textarea,
    cleanup: () => {
      terminal.dispose();
      host.remove();
    },
  };
}

function pasteEvent(data: DataTransfer) {
  return new ClipboardEvent("paste", {
    bubbles: true,
    cancelable: true,
    clipboardData: data,
  });
}

describe("browser terminal native paste ownership", () => {
  it("browser_terminal_text_paste_is_left_entirely_to_xterm", async () => {
    const { terminal, textarea, cleanup } = openTerminal();
    const ingress = vi.fn();
    const remove = installTerminalPasteInterceptor(textarea, ingress);
    const observed: string[] = [];
    const disposable = terminal.onData((value) => observed.push(value));
    await new Promise<void>((resolve) => terminal.write("\u001b[?2004h", resolve));
    const data = new DataTransfer();
    data.setData("text/plain", "first\nsecond");
    const event = pasteEvent(data);

    textarea.dispatchEvent(event);

    expect(event.defaultPrevented).toBe(false);
    expect(ingress).not.toHaveBeenCalled();
    expect(observed).toEqual(["\u001b[200~first\rsecond\u001b[201~"]);
    disposable.dispose();
    remove();
    cleanup();
  });

  it("browser_terminal_structural_event_stops_xterm", () => {
    const { terminal, textarea, cleanup } = openTerminal();
    const ingress = vi.fn();
    const remove = installTerminalPasteInterceptor(textarea, ingress);
    const observed = vi.fn();
    const disposable = terminal.onData(observed);
    const data = new DataTransfer();
    const file = new File(["image"], "screen.png", { type: "image/png" });
    data.items.add(file);
    data.setData("text/plain", "caption must not win");
    const getData = vi.spyOn(data, "getData");
    const event = pasteEvent(data);

    textarea.dispatchEvent(event);

    expect(event.defaultPrevented).toBe(true);
    expect(getData).not.toHaveBeenCalled();
    expect(observed).not.toHaveBeenCalled();
    expect(ingress).toHaveBeenCalledOnce();
    expect(ingress).toHaveBeenCalledWith([file]);
    disposable.dispose();
    remove();
    cleanup();
  });

  it("browser_terminal_paste_listener_attaches_and_cleans_up_once", () => {
    const { textarea, cleanup } = openTerminal();
    const first = vi.fn();
    const second = vi.fn();
    const removeFirst = installTerminalPasteInterceptor(textarea, first);
    removeFirst();
    const removeSecond = installTerminalPasteInterceptor(textarea, second);
    const data = new DataTransfer();
    data.items.add(new File(["x"], "x.png", { type: "image/png" }));

    textarea.dispatchEvent(pasteEvent(data));
    removeFirst();
    removeSecond();
    textarea.dispatchEvent(pasteEvent(data));

    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledOnce();
    cleanup();
  });

  it("browser_terminal_shortcuts_wait_for_authoritative_event", () => {
    const { textarea, cleanup } = openTerminal();
    const ingress = vi.fn();
    const remove = installTerminalPasteInterceptor(textarea, ingress);
    for (const init of [
      { key: "v", ctrlKey: true },
      { key: "v", metaKey: true },
      { key: "Insert", shiftKey: true },
    ]) {
      textarea.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, ...init }));
    }
    expect(ingress).not.toHaveBeenCalled();
    remove();
    cleanup();
  });

  it("browser_terminal_itemlist_is_authoritative", () => {
    const data = new DataTransfer();
    const first = new File(["1"], "same.png", { type: "image/png" });
    const second = new File(["2"], "same.png", { type: "image/png" });
    data.items.add("before", "text/plain");
    data.items.add(first);
    data.items.add("between", "text/plain");
    data.items.add(second);
    Object.defineProperty(data, "files", {
      get: () => {
        throw new Error("FileList fallback must stay unread");
      },
    });
    expect(orderedClipboardFiles(data)).toEqual([first, second]);
  });

  it("browser_terminal_distinct_files_with_same_metadata_are_preserved", () => {
    const data = new DataTransfer();
    const first = new File(["x"], "same.png", { type: "image/png", lastModified: 1 });
    const second = new File(["x"], "same.png", { type: "image/png", lastModified: 1 });
    data.items.add(first);
    data.items.add(second);
    expect(orderedClipboardFiles(data)).toEqual([first, second]);
  });

  it("browser_terminal_old_listener_is_inert_after_replacement", () => {
    const { textarea, cleanup } = openTerminal();
    const oldIngress = vi.fn();
    const currentIngress = vi.fn();
    installTerminalPasteInterceptor(textarea, oldIngress)();
    const removeCurrent = installTerminalPasteInterceptor(textarea, currentIngress);
    const data = new DataTransfer();
    data.items.add(new File(["x"], "x.png", { type: "image/png" }));
    textarea.dispatchEvent(pasteEvent(data));
    expect(oldIngress).not.toHaveBeenCalled();
    expect(currentIngress).toHaveBeenCalledOnce();
    removeCurrent();
    cleanup();
  });
});
