import {
  ClipboardWriteRateLimiter,
  planTerminalPaste,
  type TerminalReattachState,
  terminalReattachReducer,
} from "@flycockpit/relay-protocol/terminal";
import { ClipboardAddon } from "@xterm/addon-clipboard";
import { FitAddon } from "@xterm/addon-fit";
import { WebglAddon } from "@xterm/addon-webgl";
import { Terminal } from "@xterm/xterm";
import {
  type ClipboardEvent,
  type DragEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { TerminalClient, type TerminalClientStatus } from "@/lib/terminal/terminal-client";
import { useLiveTerminalStore } from "@/stores/live-terminal";

type TokenInfo = {
  token: string;
  relayUrl: string;
  expiresAt: Date | string;
};

type BrowserTerminalOptions = {
  tokenInfo: TokenInfo;
  instanceId: string;
  instanceName: string;
  cwd?: string;
  onError: (code: string) => void;
};

export type BrowserTerminalState = {
  containerRef: (node: HTMLDivElement | null) => void;
  status: TerminalClientStatus;
  viewerCount: number | null;
  recording: boolean;
  pendingClipboardText: string | null;
  uploadProgress: { sentBytes: number; totalBytes: number } | null;
  handlePaste: (event: ClipboardEvent) => void;
  handleDrop: (event: DragEvent) => void;
  confirmClipboardWrite: () => Promise<void>;
  sendInput: (data: string) => void;
  disconnect: () => void;
};

export function useBrowserTerminal(options: BrowserTerminalOptions): BrowserTerminalState {
  const elementRef = useRef<HTMLDivElement | null>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const clientRef = useRef<TerminalClient | null>(null);
  const activeIdRef = useRef<string | null>(null);
  const clipboardLimiter = useMemo(() => new ClipboardWriteRateLimiter(3, 5000), []);
  const [status, setStatus] = useState<TerminalClientStatus>("idle");
  const [viewerCount, setViewerCount] = useState<number | null>(null);
  const [recording, setRecording] = useState(false);
  const [pendingClipboardText, setPendingClipboardText] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState<{
    sentBytes: number;
    totalBytes: number;
  } | null>(null);
  const [reattach, setReattach] = useState<TerminalReattachState>({ status: "new" });
  const registerLiveTerminal = useLiveTerminalStore((s) => s.register);
  const unregisterLiveTerminal = useLiveTerminalStore((s) => s.unregister);

  const containerRef = useCallback((node: HTMLDivElement | null) => {
    elementRef.current = node;
  }, []);

  useEffect(() => {
    const element = elementRef.current;
    if (!element) return;

    const terminal = new Terminal({
      cursorBlink: true,
      convertEol: true,
      fontFamily: '"Roboto Mono", "SFMono-Regular", Consolas, monospace',
      fontSize: 14,
      scrollback: 10_000,
      theme: buildTerminalTheme(),
    });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.loadAddon(new ClipboardAddon());
    try {
      terminal.loadAddon(new WebglAddon());
    } catch {
      // Canvas rendering remains available when WebGL is unsupported or blocked.
    }
    terminal.open(element);
    fit.fit();
    terminal.focus();

    const cols = terminal.cols || 80;
    const rows = terminal.rows || 24;
    const channelId = crypto.randomUUID();
    const client = new TerminalClient({
      relayUrl: options.tokenInfo.relayUrl,
      token: options.tokenInfo.token,
      channelId,
      cwd: options.cwd,
      cols,
      rows,
      terminalId: reattach.status === "reattachable" ? reattach.terminalId : undefined,
    });

    terminalRef.current = terminal;
    fitRef.current = fit;
    clientRef.current = client;

    const dataDisposable = terminal.onData((data) => client.input(data));
    const resizeDisposable = terminal.onResize(({ cols: nextCols, rows: nextRows }) =>
      client.resize(nextCols, nextRows),
    );
    const disposers = [
      () => dataDisposable.dispose(),
      () => resizeDisposable.dispose(),
      client.on("status", (nextStatus) => {
        setStatus(nextStatus);
        if (nextStatus === "reattachable") {
          setReattach((current) => terminalReattachReducer(current, { type: "disconnect" }));
        }
      }),
      client.on("opened", (meta) => {
        setViewerCount(meta.viewerCount);
        setRecording(meta.recording);
        setReattach((current) =>
          terminalReattachReducer(current, { type: "opened", terminalId: meta.terminalId }),
        );
        const activeId = `${options.instanceId}:${meta.terminalId}`;
        activeIdRef.current = activeId;
        registerLiveTerminal({
          id: activeId,
          instanceId: options.instanceId,
          instanceName: options.instanceName,
        });
      }),
      client.on("output", (data) => terminal.write(data)),
      client.on("clipboard", (text) => {
        if (!clipboardLimiter.allow()) return;
        void navigator.clipboard.writeText(text).catch(() => setPendingClipboardText(text));
      }),
      client.on("attachmentProgress", (progress) => {
        setUploadProgress({ sentBytes: progress.receivedBytes, totalBytes: progress.totalBytes });
        if (progress.receivedBytes >= progress.totalBytes) setUploadProgress(null);
      }),
      client.on("error", (error) => options.onError(error.code)),
    ];

    const resizeObserver = new ResizeObserver(() => {
      fit.fit();
      client.resize(terminal.cols || 80, terminal.rows || 24);
    });
    resizeObserver.observe(element);

    client.connect();

    return () => {
      resizeObserver.disconnect();
      for (const dispose of disposers) dispose();
      client.close();
      terminal.dispose();
      clientRef.current = null;
      terminalRef.current = null;
      fitRef.current = null;
      const activeId = activeIdRef.current;
      if (activeId) unregisterLiveTerminal(activeId);
      activeIdRef.current = null;
    };
  }, [
    clipboardLimiter,
    options.cwd,
    options.instanceId,
    options.instanceName,
    options.onError,
    options.tokenInfo.relayUrl,
    options.tokenInfo.token,
    reattach.status,
    reattach.status === "reattachable" ? reattach.terminalId : undefined,
    registerLiveTerminal,
    unregisterLiveTerminal,
  ]);

  const pasteFiles = useCallback(
    async (files: File[]) => {
      const plan = planTerminalPaste({ files });
      if (plan.kind === "error") {
        options.onError(plan.code);
        return;
      }
      if (plan.kind !== "images") return;
      for (const image of plan.images) {
        const file = image.file as File;
        await clientRef.current?.uploadImage(file, (sentBytes, totalBytes) => {
          setUploadProgress({ sentBytes, totalBytes });
        });
      }
      setUploadProgress(null);
    },
    [options],
  );

  const handlePaste = useCallback(
    (event: ClipboardEvent) => {
      const files = Array.from(event.clipboardData.files);
      const plan = planTerminalPaste({ text: event.clipboardData.getData("text"), files });
      if (plan.kind === "empty") return;
      event.preventDefault();
      if (plan.kind === "text") {
        clientRef.current?.input(plan.text);
        return;
      }
      if (plan.kind === "error") {
        options.onError(plan.code);
        return;
      }
      void pasteFiles(files);
    },
    [options, pasteFiles],
  );

  const handleDrop = useCallback(
    (event: DragEvent) => {
      const files = Array.from(event.dataTransfer.files);
      if (files.length === 0) return;
      event.preventDefault();
      void pasteFiles(files);
    },
    [pasteFiles],
  );

  const confirmClipboardWrite = useCallback(async () => {
    if (!pendingClipboardText) return;
    await navigator.clipboard.writeText(pendingClipboardText);
    setPendingClipboardText(null);
  }, [pendingClipboardText]);

  const sendInput = useCallback((data: string) => {
    clientRef.current?.input(data);
  }, []);

  const disconnect = useCallback(() => {
    clientRef.current?.close();
    setReattach((current) => terminalReattachReducer(current, { type: "close" }));
  }, []);

  return {
    containerRef,
    status,
    viewerCount,
    recording,
    pendingClipboardText,
    uploadProgress,
    handlePaste,
    handleDrop,
    confirmClipboardWrite,
    sendInput,
    disconnect,
  };
}

function buildTerminalTheme() {
  const styles = getComputedStyle(document.documentElement);
  return {
    background: oklchVar(styles, "--background"),
    foreground: oklchVar(styles, "--foreground"),
    cursor: oklchVar(styles, "--primary"),
    selectionBackground: oklchVar(styles, "--muted"),
    black: "#111827",
    red: "#dc2626",
    green: "#16a34a",
    yellow: "#ca8a04",
    blue: "#2563eb",
    magenta: "#9333ea",
    cyan: "#0891b2",
    white: "#f9fafb",
    brightBlack: "#4b5563",
    brightRed: "#ef4444",
    brightGreen: "#22c55e",
    brightYellow: "#eab308",
    brightBlue: "#3b82f6",
    brightMagenta: "#a855f7",
    brightCyan: "#06b6d4",
    brightWhite: "#ffffff",
  };
}

function oklchVar(styles: CSSStyleDeclaration, name: string) {
  const value = styles.getPropertyValue(name).trim();
  return value ? `oklch(${value})` : undefined;
}
