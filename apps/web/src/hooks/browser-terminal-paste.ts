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
