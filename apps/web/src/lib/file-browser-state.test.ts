import { describe, expect, it } from "vitest";
import {
  canEditFile,
  childPath,
  decodeFileRoutePath,
  encodeFileRoutePath,
  normalizeProjectPath,
  parentPath,
  saveReducer,
  visibleEntries,
} from "./file-browser-state";

describe("file browser state", () => {
  it("round-trips route encoded file paths", () => {
    const path = "src/routes/a file#1.tsx";
    expect(decodeFileRoutePath(encodeFileRoutePath(path))).toBe(path);
    expect(normalizeProjectPath("/src//app/../file.ts")).toBe("src/app/../file.ts");
  });

  it("derives child and parent paths without leading slashes", () => {
    expect(childPath("src", "index.ts")).toBe("src/index.ts");
    expect(parentPath("src/routes/index.tsx")).toBe("src/routes");
    expect(parentPath("top.txt")).toBe("");
  });

  it("filters dotfiles and de-emphasizes gitignored entries after visible files", () => {
    const entries = visibleEntries(
      [
        { name: ".env", gitignored: false },
        { name: "node_modules", gitignored: true },
        { name: "src", gitignored: false },
      ],
      false,
    );
    expect(entries.map((entry) => entry.name)).toEqual(["src", "node_modules"]);
  });

  it("drives clean-dirty-saving-conflict save state", () => {
    const clean = { status: "clean", baseHash: "h1" } as const;
    const dirty = saveReducer(clean, { type: "edit" });
    const saving = saveReducer(dirty, { type: "save" });
    const conflict = saveReducer(saving, { type: "conflict", message: "hash_mismatch" });
    expect(conflict).toEqual({ status: "conflict", baseHash: "h1", message: "hash_mismatch" });
    expect(saveReducer(saving, { type: "saved", hash: "h2" })).toEqual({
      status: "saved",
      baseHash: "h2",
    });
  });

  it("gates edit affordances by scope verdict and file kind", () => {
    expect(canEditFile({ connected: true, blocked: false, kind: "text" })).toBe(true);
    expect(canEditFile({ connected: true, blocked: true, kind: "text" })).toBe(false);
    expect(canEditFile({ connected: true, blocked: false, kind: "binary" })).toBe(false);
  });
});
