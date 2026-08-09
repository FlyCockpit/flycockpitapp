import { createHash, createHmac } from "node:crypto";
import { lstat, open, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, parse } from "node:path";
import { canonicalizeRfc8785 } from "@flycockpit/cockpit-protocol";

export interface RemoteFallbackRouteBindingKeyV1 {
  generation: string;
  keyBase64url: string;
  state: "current" | "previous";
  activatedAt: string;
  retireAt: string | null;
}
export interface RemoteFallbackRouteBindingKeyFileV1 {
  schemaVersion: 1;
  revision: string;
  currentGeneration: string;
  keys: RemoteFallbackRouteBindingKeyV1[];
}
export interface RemoteFallbackRouteKeyWatermark {
  revision: string;
  currentGeneration: string;
  fileDigest: string;
}
export interface RemoteFallbackWatermarkDb {
  $queryRawUnsafe<T>(query: string, ...values: unknown[]): Promise<T>;
  $executeRawUnsafe(query: string, ...values: unknown[]): Promise<number>;
  $transaction<T>(
    callback: (database: RemoteFallbackWatermarkDb) => Promise<T>,
    options?: { isolationLevel?: "Serializable" },
  ): Promise<T>;
}

const decimal = /^(0|[1-9][0-9]*)$/;
const signedDecimal = /^(0|-?[1-9][0-9]*)$/;
function text(value: unknown, name: string, signed = false): string {
  if (typeof value !== "string" || !(signed ? signedDecimal : decimal).test(value))
    throw new Error(`invalid_${name}`);
  const parsed = BigInt(value);
  if (
    (!signed && parsed > 0xffffffffffffffffn) ||
    (signed && (parsed < -(1n << 63n) || parsed > (1n << 63n) - 1n))
  )
    throw new Error(`invalid_${name}`);
  return value;
}
function exactObject(
  value: unknown,
  keys: readonly string[],
  name: string,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error(`invalid_${name}`);
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join("\0") !== [...keys].sort().join("\0"))
    throw new Error(`invalid_${name}_fields`);
  return record;
}

export function parseRemoteFallbackRouteBindingKeys(
  raw: unknown,
): RemoteFallbackRouteBindingKeyFileV1 {
  const root = exactObject(
    raw,
    ["schemaVersion", "revision", "currentGeneration", "keys"],
    "route_key_file",
  );
  if (
    root.schemaVersion !== 1 ||
    !Array.isArray(root.keys) ||
    root.keys.length < 1 ||
    root.keys.length > 2
  )
    throw new Error("invalid_route_key_file");
  const revision = text(root.revision, "revision");
  const currentGeneration = text(root.currentGeneration, "current_generation");
  const seenGenerations = new Set<string>();
  const seenMaterial = new Set<string>();
  const keys = root.keys
    .map((item) => {
      const key = exactObject(
        item,
        ["generation", "keyBase64url", "state", "activatedAt", "retireAt"],
        "route_key",
      );
      const generation = text(key.generation, "key_generation");
      const activatedAt = text(key.activatedAt, "activated_at", true);
      const retireAt = key.retireAt === null ? null : text(key.retireAt, "retire_at", true);
      if (
        typeof key.keyBase64url !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(key.keyBase64url) ||
        Buffer.from(key.keyBase64url, "base64url").length !== 32 ||
        Buffer.from(key.keyBase64url, "base64url").toString("base64url") !== key.keyBase64url
      )
        throw new Error("invalid_route_key_material");
      if (key.state !== "current" && key.state !== "previous")
        throw new Error("invalid_route_key_state");
      const state: "current" | "previous" = key.state;
      if (seenGenerations.has(generation) || seenMaterial.has(key.keyBase64url))
        throw new Error("duplicate_route_key");
      seenGenerations.add(generation);
      seenMaterial.add(key.keyBase64url);
      return {
        generation,
        keyBase64url: key.keyBase64url,
        state,
        activatedAt,
        retireAt,
      };
    })
    .sort((a, b) => (BigInt(a.generation) < BigInt(b.generation) ? -1 : 1));
  if (
    keys.filter((key) => key.state === "current").length !== 1 ||
    keys.filter((key) => key.state === "previous").length > 1 ||
    keys.find((key) => key.state === "current")?.generation !== currentGeneration
  )
    throw new Error("invalid_route_key_roles");
  if (
    BigInt(revision) < 1n ||
    BigInt(currentGeneration) < 1n ||
    keys.some((key) => BigInt(key.generation) < 1n)
  )
    throw new Error("zero_route_key_generation");
  if (keys.length === 2 && BigInt(keys[1]!.generation) !== BigInt(keys[0]!.generation) + 1n)
    throw new Error("nonunit_route_key_generation");
  return { schemaVersion: 1, revision, currentGeneration, keys };
}

export function remoteFallbackRouteBindingKeyDigest(
  file: RemoteFallbackRouteBindingKeyFileV1,
): string {
  const metadata = {
    ...file,
    keys: file.keys.map((key) => ({
      ...key,
      keyBase64url: createHash("sha256")
        .update(Buffer.from(key.keyBase64url, "base64url"))
        .digest("hex"),
    })),
  };
  return createHash("sha256").update(canonicalizeRfc8785(metadata)).digest("hex");
}

export function validateRemoteFallbackRouteKeyWatermark(
  file: RemoteFallbackRouteBindingKeyFileV1,
  watermark: RemoteFallbackRouteKeyWatermark | null,
): RemoteFallbackRouteKeyWatermark {
  const fileDigest = remoteFallbackRouteBindingKeyDigest(file);
  if (watermark) {
    const revision = BigInt(file.revision),
      priorRevision = BigInt(watermark.revision);
    const generation = BigInt(file.currentGeneration),
      priorGeneration = BigInt(watermark.currentGeneration);
    if (
      revision < priorRevision ||
      generation < priorGeneration ||
      generation > priorGeneration + 1n ||
      (revision === priorRevision && fileDigest !== watermark.fileDigest)
    )
      throw new Error("route_key_rollback_or_changed_revision");
  }
  return { revision: file.revision, currentGeneration: file.currentGeneration, fileDigest };
}

export function remoteFallbackAttachmentBinding(
  file: RemoteFallbackRouteBindingKeyFileV1,
  generation: string,
  tenantId: Uint8Array,
  logicalAttachmentId: Uint8Array,
): Uint8Array {
  if (tenantId.length !== 16 || logicalAttachmentId.length !== 16)
    throw new Error("invalid_attachment_coordinates");
  const key = file.keys.find((candidate) => candidate.generation === generation);
  if (!key) throw new Error("missing_route_binding_generation");
  return createHmac("sha256", Buffer.from(key.keyBase64url, "base64url"))
    .update("flycockpit.remote.fallback.attachment.v1\0")
    .update(tenantId)
    .update(logicalAttachmentId)
    .digest();
}

export function canRetireRemoteFallbackPreviousKey(input: {
  key: RemoteFallbackRouteBindingKeyV1;
  nowMillis: bigint;
  latestReferencedExpiryMillis: bigint | null;
}): boolean {
  if (input.key.state !== "previous" || input.key.retireAt === null) return false;
  const configuredRetirement = BigInt(input.key.retireAt);
  const referenceFence = (input.latestReferencedExpiryMillis ?? 0n) + 60_000n;
  return input.nowMillis >= configuredRetirement && input.nowMillis >= referenceFence;
}

export interface RemoteFallbackRouteKeyReferenceStore {
  latestReferencedExpiryMillis(generation: string): Promise<bigint | null>;
}
export async function assertRemoteFallbackPreviousKeyRetirable(input: {
  key: RemoteFallbackRouteBindingKeyV1;
  nowMillis: bigint;
  references: RemoteFallbackRouteKeyReferenceStore;
}): Promise<void> {
  const latestReferencedExpiryMillis = await input.references.latestReferencedExpiryMillis(
    input.key.generation,
  );
  if (
    !canRetireRemoteFallbackPreviousKey({
      key: input.key,
      nowMillis: input.nowMillis,
      latestReferencedExpiryMillis,
    })
  )
    throw new Error("route_binding_key_still_referenced");
}

export async function readRemoteFallbackRouteBindingKeys(
  path: string,
): Promise<RemoteFallbackRouteBindingKeyFileV1> {
  if (!isAbsolute(path)) throw new Error("route key file must be absolute");
  const parent = dirname(path);
  for (let current = parent; ; current = dirname(current)) {
    const info = await lstat(current);
    const unsafeWritable =
      (info.mode & 0o022) !== 0 && !((info.mode & 0o1000) !== 0 && info.uid === 0);
    if (!info.isDirectory() || info.isSymbolicLink() || unsafeWritable)
      throw new Error("route key parent is unsafe");
    if (current === parse(current).root) break;
  }
  if ((await realpath(parent)) !== parent) throw new Error("route key parent traverses symlink");
  const before = await lstat(path);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    (before.mode & 0o077) !== 0 ||
    (typeof process.getuid === "function" && before.uid !== process.getuid())
  )
    throw new Error("route key file is unsafe");
  const handle = await open(path, "r");
  try {
    const opened = await handle.stat();
    if (opened.dev !== before.dev || opened.ino !== before.ino)
      throw new Error("route key file changed during open");
    const raw: unknown = JSON.parse(await handle.readFile("utf8"));
    const after = await stat(path);
    if (
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.mtimeMs !== opened.mtimeMs ||
      after.size !== opened.size
    )
      throw new Error("route key file changed during read");
    return parseRemoteFallbackRouteBindingKeys(raw);
  } finally {
    await handle.close();
  }
}

export async function persistRemoteFallbackRouteKeyWatermark(
  database: RemoteFallbackWatermarkDb,
  deploymentId: string,
  file: RemoteFallbackRouteBindingKeyFileV1,
): Promise<RemoteFallbackRouteKeyWatermark> {
  return database.$transaction(
    async (tx) => {
      const rows = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
        `SELECT "highestRevision","currentGeneration","fileDigest" FROM "remote_fallback_route_key_watermarks" WHERE "deploymentId"=$1 FOR UPDATE`,
        deploymentId,
      );
      const row = rows[0];
      const prior = row
        ? {
            revision: String(row.highestRevision),
            currentGeneration: String(row.currentGeneration),
            fileDigest: String(row.fileDigest),
          }
        : null;
      const next = validateRemoteFallbackRouteKeyWatermark(file, prior);
      await tx.$executeRawUnsafe(
        `INSERT INTO "remote_fallback_route_key_watermarks" ("deploymentId","highestRevision","currentGeneration","fileDigest","updatedAt") VALUES ($1,$2::numeric,$3::numeric,$4,NOW()) ON CONFLICT ("deploymentId") DO UPDATE SET "highestRevision"=EXCLUDED."highestRevision","currentGeneration"=EXCLUDED."currentGeneration","fileDigest"=EXCLUDED."fileDigest","updatedAt"=NOW()`,
        deploymentId,
        next.revision,
        next.currentGeneration,
        next.fileDigest,
      );
      return next;
    },
    { isolationLevel: "Serializable" },
  );
}

export async function loadRemoteFallbackRouteBindingKeyRuntime(input: {
  path: string | undefined;
  expectedDigest: string | undefined;
  deploymentId: string;
  database: RemoteFallbackWatermarkDb;
}): Promise<{
  file: RemoteFallbackRouteBindingKeyFileV1;
  watermark: RemoteFallbackRouteKeyWatermark;
}> {
  if (!input.path || !input.expectedDigest)
    throw new Error("remote_fallback_route_keys_unconfigured");
  const file = await readRemoteFallbackRouteBindingKeys(input.path);
  const digest = remoteFallbackRouteBindingKeyDigest(file);
  if (digest !== input.expectedDigest) throw new Error("remote_fallback_route_key_digest_mismatch");
  const watermark = await persistRemoteFallbackRouteKeyWatermark(
    input.database,
    input.deploymentId,
    file,
  );
  return { file, watermark };
}
