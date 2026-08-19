import { lstat, open, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, parse } from "node:path";
import {
  type AuthorityRingFile,
  authorityRingFileDigest,
  parseAuthorityRingFile,
} from "./remote-authority";

// -----------------------------------------------------------------------------
// DEVELOPMENT / BOOTSTRAP ONLY.
//
// This provider reads an authority signing ring from a local JSON file whose keys
// carry the plaintext private scalar `d`. That is acceptable only for local dev
// and first-boot bootstrap. Production deployments MUST keep private key material
// in a KMS/HSM and sign through the non-extractable provider path
// (`InjectedAuthoritySigner` in ./remote-authority, driven by a KMS-backed
// signer) so the private scalar never lands on disk or in process memory here.
// See remote-authority-kms.test.ts for the provider-native signing contract.
// -----------------------------------------------------------------------------

/** Read one complete owner-private regular file without following a final symlink. */
export async function readAuthorityRingFile(
  path: string,
  previousRevision?: string,
  previousRing?: AuthorityRingFile,
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
    const parsed = parseAuthorityRingFile(raw);
    if (previousRevision !== undefined && BigInt(parsed.revision) <= BigInt(previousRevision)) {
      if (
        parsed.revision === previousRevision &&
        previousRing &&
        authorityRingFileDigest(parsed) === authorityRingFileDigest(previousRing)
      )
        return parsed;
      throw new Error("authority ring revision is nonmonotonic or reused with changed bytes");
    }
    return parsed;
  } finally {
    await handle.close();
  }
}
