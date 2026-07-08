export type SaveState =
  | { status: "clean"; baseHash: string | null }
  | { status: "dirty"; baseHash: string | null }
  | { status: "saving"; baseHash: string | null }
  | { status: "conflict"; baseHash: string | null; message: string }
  | { status: "saved"; baseHash: string };

export function normalizeProjectPath(path: string | undefined | null) {
  const raw = (path ?? "").replaceAll("\\", "/").trim();
  if (!raw || raw === "." || raw === "/") return "";
  return raw
    .split("/")
    .filter((part) => part && part !== ".")
    .join("/");
}

export function encodeFileRoutePath(path: string) {
  return encodeURIComponent(normalizeProjectPath(path));
}

export function decodeFileRoutePath(value: string | undefined) {
  return normalizeProjectPath(value ? decodeURIComponent(value) : "");
}

export function parentPath(path: string) {
  const normalized = normalizeProjectPath(path);
  const parts = normalized.split("/").filter(Boolean);
  parts.pop();
  return parts.join("/");
}

export function childPath(base: string, name: string) {
  return normalizeProjectPath([normalizeProjectPath(base), name].filter(Boolean).join("/"));
}

export function visibleEntries<T extends { name: string; gitignored: boolean }>(
  entries: T[],
  showHidden: boolean,
) {
  return [...entries]
    .filter((entry) => showHidden || !entry.name.startsWith("."))
    .sort((a, b) => Number(a.gitignored) - Number(b.gitignored) || a.name.localeCompare(b.name));
}

export function canEditFile(input: { connected: boolean; blocked: boolean; kind: string }) {
  return input.connected && !input.blocked && input.kind === "text";
}

export function saveReducer(
  state: SaveState,
  event:
    | { type: "edit" }
    | { type: "save" }
    | { type: "saved"; hash: string }
    | { type: "conflict"; message: string },
) {
  if (event.type === "edit")
    return { status: "dirty", baseHash: state.baseHash } satisfies SaveState;
  if (event.type === "save")
    return { status: "saving", baseHash: state.baseHash } satisfies SaveState;
  if (event.type === "saved") return { status: "saved", baseHash: event.hash } satisfies SaveState;
  return {
    status: "conflict",
    baseHash: state.baseHash,
    message: event.message,
  } satisfies SaveState;
}
