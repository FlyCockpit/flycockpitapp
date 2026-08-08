import { lstat, open, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, parse } from "node:path";
import { type AuthorityRingFile, parseAuthorityRingFile } from "./remote-authority";

/** Read one complete owner-private regular file without following a final symlink. */
export async function readAuthorityRingFile(
  path: string,
  previousRevision?: string,
): Promise<AuthorityRingFile> {
  if (!isAbsolute(path)) throw new Error("REMOTE_GRANT_SIGNING_KEY_FILE must be absolute");
  const parent = dirname(path);
  for (let current = parent; ; current = dirname(current)) {
    const info = await lstat(current),
      writable = (info.mode & 0o022) !== 0,
      protectedStickyDirectory = info.isDirectory() && (info.mode & 0o1000) !== 0 && info.uid === 0;
    if (info.isSymbolicLink() || !info.isDirectory() || (writable && !protectedStickyDirectory))
      throw new Error("authority ring parent is unsafe");
    if (current === parse(current).root) break;
  }
  const parentReal = await realpath(parent);
  if (parentReal !== parent) throw new Error("authority ring parent must not traverse symlinks");
  const before = await lstat(path);
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    (before.mode & 0o077) !== 0 ||
    (typeof process.getuid === "function" && before.uid !== process.getuid())
  )
    throw new Error("authority ring must be an owner-private regular file");
  const handle = await open(path, "r");
  try {
    const opened = await handle.stat();
    if (opened.dev !== before.dev || opened.ino !== before.ino)
      throw new Error("authority ring changed during open");
    const text = await handle.readFile("utf8");
    const after = await stat(path);
    if (
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.mtimeMs !== opened.mtimeMs ||
      after.size !== opened.size
    )
      throw new Error("authority ring changed during read");
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch {
      throw new Error("authority ring is not JSON");
    }
    return parseAuthorityRingFile(raw, previousRevision);
  } finally {
    await handle.close();
  }
}
