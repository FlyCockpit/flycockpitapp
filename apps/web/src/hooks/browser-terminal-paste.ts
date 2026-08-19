export type TerminalPasteIngress = (files: readonly File[]) => void;

export function orderedClipboardFiles(data: DataTransfer): File[] {
  const fromItems: File[] = [];
  const seenItems = new Set<File>();
  const items = data.items;
  if (items) {
    for (let index = 0; index < items.length; index += 1) {
      const item = items[index];
      if (item?.kind !== "file") continue;
      const file = item.getAsFile();
      if (file && !seenItems.has(file)) {
        seenItems.add(file);
        fromItems.push(file);
      }
    }
  }
  if (fromItems.length > 0) return fromItems;

  const fromFiles: File[] = [];
  const seenFiles = new Set<File>();
  for (let index = 0; index < data.files.length; index += 1) {
    const file = data.files.item(index);
    if (file && !seenFiles.has(file)) {
      seenFiles.add(file);
      fromFiles.push(file);
    }
  }
  return fromFiles;
}

export function installTerminalPasteInterceptor(
  textarea: HTMLTextAreaElement,
  ingress: TerminalPasteIngress,
): () => void {
  let active = true;
  const listener = (event: globalThis.ClipboardEvent) => {
    if (!active || !event.clipboardData) return;
    const files = orderedClipboardFiles(event.clipboardData);
    if (files.length === 0) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    ingress(files);
  };
  textarea.addEventListener("paste", listener, { capture: true });
  return () => {
    active = false;
    textarea.removeEventListener("paste", listener, { capture: true });
  };
}

/**
 * Build the terminal drop handler used by {@link useBrowserTerminal}.
 *
 * The handler treats a multi-file drop as a single whole-gesture paste: it
 * extracts every file from `DataTransfer.files` and forwards the complete
 * array to `pasteFiles` in one call. A map-split implementation that called
 * `pasteFiles([file])` per file would violate the whole-gesture contract
 * (each single image would be accepted instead of one `too_many_files`
 * rejection), so this factory is the single production path tests exercise.
 *
 * The event parameter is a structural subset of both the native `DragEvent`
 * and React's `React.DragEvent`, so the same handler attaches to a raw DOM
 * textarea (in tests) and to a React `onDrop` prop (in production) without
 * adapter shims.
 */
export type TerminalDropEvent = {
  readonly dataTransfer: DataTransfer | null;
  preventDefault(): void;
};

export function createTerminalDropHandler(
  pasteFiles: TerminalPasteIngress,
): (event: TerminalDropEvent) => void {
  return (event) => {
    const files = Array.from(event.dataTransfer?.files ?? []);
    if (files.length === 0) return;
    event.preventDefault();
    pasteFiles(files);
  };
}
