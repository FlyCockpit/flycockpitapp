import { lstat, open, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute } from "node:path";
import { type AuthorityRingFile, parseAuthorityRingFile } from "./remote-authority";

/** Read one complete owner-private regular file without following a final symlink. */
export async function readAuthorityRingFile(
  path: string,
  previousRevision?: string,
): Promise<AuthorityRingFile> {
  if (!isAbsolute(path)) throw new Error("REMOTE_GRANT_SIGNING_KEY_FILE must be absolute");
  const parent = dirname(path),
    parentInfo = await lstat(parent);
  if (parentInfo.isSymbolicLink() || !parentInfo.isDirectory() || (parentInfo.mode & 0o022) !== 0)
    throw new Error("authority ring parent is unsafe");
  const parentReal = await realpath(parent);
  if (parentReal !== parent) throw new Error("authority ring parent must not traverse symlinks");
  const before = await lstat(path);
  if (before.isSymbolicLink() || !before.isFile() || (before.mode & 0o077) !== 0)
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
