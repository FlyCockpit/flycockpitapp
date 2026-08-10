import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { orderedClipboardFiles } from "./browser-terminal-paste";

function item(file: File | null): DataTransferItem {
  return {
    kind: "file",
    type: file?.type ?? "",
    getAsFile: () => file,
    getAsString: () => undefined,
    webkitGetAsEntry: () => null,
  };
}

function stringItem(): DataTransferItem {
  return {
    kind: "string",
    type: "text/plain",
    getAsFile: () => null,
    getAsString: (callback) => callback?.("caption"),
    webkitGetAsEntry: () => null,
  };
}

function transfer(items: readonly DataTransferItem[], files: readonly File[]): DataTransfer {
  const fileList = {
    ...files,
    length: files.length,
    item: (index: number) => files[index] ?? null,
    [Symbol.iterator]: () => files[Symbol.iterator](),
  } as unknown as FileList;
  return {
    items: items as unknown as DataTransferItemList,
    files: fileList,
  } as DataTransfer;
}

describe("browser terminal ordered clipboard classifier", () => {
  it("browser_terminal_filelist_fallback", () => {
    const first = new File(["1"], "first.png", { type: "image/png" });
    const second = new File(["2"], "second.png", { type: "image/png" });
    expect(orderedClipboardFiles(transfer([], [first, first, second]))).toEqual([first, second]);
    expect(orderedClipboardFiles(transfer([item(null)], [second, first]))).toEqual([second, first]);
    expect(orderedClipboardFiles(transfer([stringItem()], [first]))).toEqual([first]);
    expect(orderedClipboardFiles(transfer([item(null)], []))).toEqual([]);
    const unavailable = transfer([], [second]);
    Object.defineProperty(unavailable, "items", { value: undefined });
    expect(orderedClipboardFiles(unavailable)).toEqual([second]);
  });

  it("does not merge FileList into a usable item-list result", () => {
    const itemFile = new File(["1"], "item.png", { type: "image/png" });
    const fallback = new File(["2"], "fallback.png", { type: "image/png" });
    expect(orderedClipboardFiles(transfer([item(null), item(itemFile)], [fallback]))).toEqual([
      itemFile,
    ]);
  });
});

describe("browser terminal paste source contracts", () => {
  it("browser_terminal_tests_corrected_first", () => {
    const root = resolve(import.meta.dirname, "../../../..");
    const hook = readFileSync(resolve(root, "apps/web/src/hooks/use-browser-terminal.ts"), "utf8");
    const route = readFileSync(
      resolve(root, "apps/web/src/routes/$lang/_auth/instances.$instanceId.terminal.tsx"),
      "utf8",
    );
    const planner = readFileSync(resolve(root, "packages/relay-protocol/src/terminal.ts"), "utf8");
    const interceptor = readFileSync(
      resolve(root, "apps/web/src/hooks/browser-terminal-paste.ts"),
      "utf8",
    );
    const packageJson = JSON.parse(
      readFileSync(resolve(root, "apps/web/package.json"), "utf8"),
    ) as { scripts: Record<string, string> };
    expect(hook).not.toContain("handlePaste");
    expect(hook).not.toContain('getData("text")');
    expect(route).not.toContain("onPaste=");
    expect(planner).not.toContain("text?: string");
    expect(planner).not.toContain('kind: "images"');
    expect(packageJson.scripts["test:node"]).toBe("vitest run --config vitest.node.config.ts");
    expect(packageJson.scripts["test:browser"]).toBe(
      "vitest run --config vitest.browser.config.ts",
    );
    expect(packageJson.scripts.test).toBe("pnpm run test:node && pnpm run test:browser");
    expect(JSON.stringify(packageJson.scripts)).not.toContain("passWithNoTests");
    expect(hook.indexOf("terminal.open(element)")).toBeLessThan(
      hook.indexOf("installTerminalPasteInterceptor(textarea"),
    );
    expect(hook.indexOf("installTerminalPasteInterceptor(textarea")).toBeLessThan(
      hook.indexOf("terminal.onData"),
    );
    expect(hook.indexOf("terminal.onData")).toBeLessThan(hook.indexOf("client.connect()"));
    expect(interceptor).toContain('addEventListener("paste", listener, { capture: true })');
    expect(interceptor).toContain('removeEventListener("paste", listener, { capture: true })');
  });

  it("browser_terminal_native_fixture_environment", () => {
    const root = resolve(import.meta.dirname, "../../../..");
    const browserConfig = readFileSync(resolve(root, "apps/web/vitest.browser.config.ts"), "utf8");
    const nodeConfig = readFileSync(resolve(root, "apps/web/vitest.node.config.ts"), "utf8");
    const workflow = readFileSync(resolve(root, ".github/workflows/pr-checks.yml"), "utf8");
    expect(browserConfig).toContain('browser: "chromium"');
    expect(browserConfig).toContain("playwright()");
    expect(browserConfig).toContain("passWithNoTests: false");
    expect(nodeConfig).toContain('exclude: ["**/*.browser.test.{ts,tsx}"]');
    expect(nodeConfig).toContain("passWithNoTests: false");
    expect(workflow).toContain("pnpm --filter web exec playwright install --with-deps chromium");
  });

  it("browser_terminal_listener_targets_xterm_textarea_capture_phase", () => {
    const root = resolve(import.meta.dirname, "../../../..");
    const hook = readFileSync(resolve(root, "apps/web/src/hooks/use-browser-terminal.ts"), "utf8");
    const interceptor = readFileSync(
      resolve(root, "apps/web/src/hooks/browser-terminal-paste.ts"),
      "utf8",
    );
    expect(hook).toContain("const textarea = terminal.textarea");
    expect(hook.indexOf("terminal.open(element)")).toBeLessThan(
      hook.indexOf("installTerminalPasteInterceptor(textarea"),
    );
    expect(hook.indexOf("installTerminalPasteInterceptor(textarea")).toBeLessThan(
      hook.indexOf("client.connect()"),
    );
    expect(interceptor).toContain("event.stopImmediatePropagation()");
  });
});
