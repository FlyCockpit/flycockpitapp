/**
 * Authorization-scoped remote protocol identifier allocation and resolution.
 * @see remote-protocol-identifier-foundation
 *
 * Domain prompts authorize against source rows, then mint a typed capability via
 * the factories below. Capability tokens are opaque frozen objects; grant data
 * lives only in a module-private WeakMap (not on the token). This module never
 * lists, probes, or places source IDs on the wire.
 */
import { randomBytes } from "node:crypto";
import {
  encodeProtocolIdBase64Url,
  isRemoteProtocolIdKind,
  protocolIdKindOf,
  REMOTE_PROTOCOL_ID_BYTES,
  type RemoteProtocolIdBytes,
  type RemoteProtocolIdKind,
  tagProtocolIdBytes,
} from "@flycockpit/cockpit-protocol";
import type prisma from "@flycockpit/db";

export type { RemoteProtocolIdKind };

/** Default Prisma client type from `@flycockpit/db` (default export instance). */
type PrismaClient = typeof prisma;
type PrismaTx = Parameters<Parameters<PrismaClient["$transaction"]>[0]>[0];

const MAX_COLLISION_RETRIES = 8;

/** Module-private brand — not Symbol.for. */
const AUTH_BRAND = Symbol("RemoteProtocolAuthz");

type AuthzData = {
  readonly mode: "system" | "tenant";
  readonly tenantSourceId?: string;
  readonly allowedKinds: readonly RemoteProtocolIdKind[];
  /** kind → frozen list of authorized source IDs (never exposed on the token). */
  readonly authorizedSourceIds: Readonly<Partial<Record<RemoteProtocolIdKind, readonly string[]>>>;
};

/** Opaque frozen capability token — grant data is NOT on this object. */
export type RemoteProtocolAuthz = {
  readonly [AUTH_BRAND]: true;
};

/** Grant store keyed by issued tokens (not forgeable without registry membership). */
const authzStore = new WeakMap<object, AuthzData>();

export class RemoteProtocolIdentifierDenied extends Error {
  readonly code = "REMOTE_PROTOCOL_ID_DENIED" as const;
  constructor() {
    super("remote protocol identifier denied");
    this.name = "RemoteProtocolIdentifierDenied";
  }
}

function mintAuthz(data: AuthzData): RemoteProtocolAuthz {
  const kinds = Object.freeze([...data.allowedKinds]) as readonly RemoteProtocolIdKind[];
  const sourceIds: Partial<Record<RemoteProtocolIdKind, readonly string[]>> = {};
  for (const [k, list] of Object.entries(data.authorizedSourceIds) as [
    RemoteProtocolIdKind,
    readonly string[] | undefined,
  ][]) {
    if (list) {
      sourceIds[k] = Object.freeze([...list]);
    }
  }
  const stored: AuthzData = Object.freeze({
    mode: data.mode,
    tenantSourceId: data.tenantSourceId,
    allowedKinds: kinds,
    authorizedSourceIds: Object.freeze(sourceIds),
  });
  const token = Object.freeze({ [AUTH_BRAND]: true as const });
  authzStore.set(token, stored);
  return token;
}

function loadAuthz(authz: RemoteProtocolAuthz): AuthzData {
  if (typeof authz !== "object" || authz === null || authz[AUTH_BRAND] !== true) {
    throw new RemoteProtocolIdentifierDenied();
  }
  const data = authzStore.get(authz);
  if (!data) {
    throw new RemoteProtocolIdentifierDenied();
  }
  return data;
}

/** System capability — composition roots / tests only. */
export function systemRemoteProtocolAuthz(): RemoteProtocolAuthz {
  return mintAuthz({
    mode: "system",
    allowedKinds: ["tenant", "account", "instance", "project"],
    authorizedSourceIds: {},
  });
}

/**
 * Tenant-scoped capability. Domain code must already have authorized the actor
 * against each listed source row before minting.
 */
export function tenantRemoteProtocolAuthz(opts: {
  tenantSourceId: string;
  allowedKinds: readonly RemoteProtocolIdKind[];
  authorizedSourceIds: Partial<Record<RemoteProtocolIdKind, readonly string[]>>;
}): RemoteProtocolAuthz {
  if (!opts.tenantSourceId) {
    throw new Error("tenantSourceId required");
  }
  const authorizedSourceIds: Partial<Record<RemoteProtocolIdKind, readonly string[]>> = {
    ...opts.authorizedSourceIds,
  };
  // Tenant kind is always exactly the capability's tenantSourceId — never a list
  // of foreign tenants, even if the caller tries to inject them.
  if (opts.allowedKinds.includes("tenant")) {
    authorizedSourceIds.tenant = [opts.tenantSourceId];
  } else {
    delete authorizedSourceIds.tenant;
  }
  return mintAuthz({
    mode: "tenant",
    tenantSourceId: opts.tenantSourceId,
    allowedKinds: [...opts.allowedKinds],
    authorizedSourceIds,
  });
}

function assertKindAndSourceAuthorized(
  authz: RemoteProtocolAuthz,
  kind: RemoteProtocolIdKind,
  sourceId: string,
): void {
  if (!isRemoteProtocolIdKind(kind)) {
    throw new RemoteProtocolIdentifierDenied();
  }
  const data = loadAuthz(authz);
  if (data.mode === "system") return;
  if (!data.allowedKinds.includes(kind)) {
    throw new RemoteProtocolIdentifierDenied();
  }
  if (kind === "tenant" && sourceId !== data.tenantSourceId) {
    throw new RemoteProtocolIdentifierDenied();
  }
  const allowed = data.authorizedSourceIds[kind];
  if (!allowed?.includes(sourceId)) {
    throw new RemoteProtocolIdentifierDenied();
  }
}

function assertKindAllowed(authz: RemoteProtocolAuthz, kind: RemoteProtocolIdKind): void {
  if (!isRemoteProtocolIdKind(kind)) {
    throw new RemoteProtocolIdentifierDenied();
  }
  const data = loadAuthz(authz);
  if (data.mode === "system") return;
  if (!data.allowedKinds.includes(kind)) {
    throw new RemoteProtocolIdentifierDenied();
  }
}

function isAllZero(bytes: Uint8Array | Buffer): boolean {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) return false;
  }
  return true;
}

function freshProtocolIdBytes(): Buffer {
  for (let i = 0; i < 16; i++) {
    // Always CSPRNG — no production override path.
    const raw = new Uint8Array(randomBytes(REMOTE_PROTOCOL_ID_BYTES));
    if (raw.length !== REMOTE_PROTOCOL_ID_BYTES) {
      throw new Error("protocol id entropy length mismatch");
    }
    if (!isAllZero(raw)) {
      return Buffer.from(raw);
    }
  }
  throw new Error("protocol id entropy exhausted all-zero retries");
}

function isUniqueViolation(e: unknown, field: "protocolId" | "sourceId" | "any"): boolean {
  if (!e || typeof e !== "object") return false;
  const err = e as { code?: string; meta?: { target?: string[] | string }; message?: string };
  const msg = err.message ?? "";
  const target = err.meta?.target;
  const joined = Array.isArray(target) ? target.join(",") : String(target ?? "");
  const isP2002 = err.code === "P2002" || /Unique constraint/i.test(msg);
  if (!isP2002) return false;
  if (field === "any") return true;
  if (field === "protocolId") {
    return /protocolId|protocol_id/i.test(joined) || /protocolId|protocol_id/i.test(msg);
  }
  return (
    /sourceId|source_id/i.test(joined) ||
    /sourceId|source_id/i.test(msg) ||
    (/kind/i.test(joined) && !/protocolId|protocol_id/i.test(joined))
  );
}

function isSerializationFailure(e: unknown): boolean {
  if (e && typeof e === "object") {
    const err = e as { code?: string; message?: string };
    if (err.code === "P2034") return true;
    if (/could not serialize|serialization failure|write conflict/i.test(err.message ?? "")) {
      return true;
    }
  }
  return false;
}

/**
 * Allocate or return existing protocol alias for (kind, sourceId).
 * Serializable, idempotent, CSPRNG 16-byte protocolId.
 * Returns kind-branded bytes so kind confusion is a type error.
 */
export async function allocateRemoteProtocolIdentifier<K extends RemoteProtocolIdKind>(
  db: PrismaClient,
  kind: K,
  sourceId: string,
  authz: RemoteProtocolAuthz,
): Promise<RemoteProtocolIdBytes<K>> {
  assertKindAndSourceAuthorized(authz, kind, sourceId);
  if (!sourceId || sourceId.length < 1) {
    throw new Error("sourceId required");
  }

  for (let attempt = 0; attempt < MAX_COLLISION_RETRIES; attempt++) {
    try {
      const row = await db.$transaction(
        async (tx: PrismaTx) => {
          const existing = await tx.remoteProtocolIdentifier.findUnique({
            where: { kind_sourceId: { kind, sourceId } },
          });
          if (existing) {
            if (existing.retiredAt || existing.sourceId === null) {
              throw new RemoteProtocolIdentifierDenied();
            }
            // Idempotent hit: no fresh entropy required.
            return existing.protocolId;
          }
          const protocolId = freshProtocolIdBytes();
          const created = await tx.remoteProtocolIdentifier.create({
            data: {
              kind,
              sourceId,
              protocolId: new Uint8Array(protocolId),
            },
          });
          return created.protocolId;
        },
        { isolationLevel: "Serializable" },
      );
      return tagProtocolIdBytes(kind, new Uint8Array(row));
    } catch (e: unknown) {
      if (e instanceof RemoteProtocolIdentifierDenied) {
        throw e;
      }
      if (isUniqueViolation(e, "sourceId")) {
        const winner = await db.remoteProtocolIdentifier.findUnique({
          where: { kind_sourceId: { kind, sourceId } },
        });
        if (winner && !winner.retiredAt && winner.sourceId !== null) {
          return tagProtocolIdBytes(kind, new Uint8Array(winner.protocolId));
        }
        if (winner?.retiredAt || winner?.sourceId === null) {
          throw new RemoteProtocolIdentifierDenied();
        }
        continue;
      }
      if (isUniqueViolation(e, "protocolId") || isSerializationFailure(e)) {
        continue;
      }
      throw e;
    }
  }
  throw new Error("remote protocol id allocation exhausted collision retries");
}

/**
 * Inbound resolve: exact kind + kind-branded 16 bytes within authorized scope.
 * Kind confusion fails before any database work. Tenant lookups are constrained
 * to the capability's authorized source IDs (no global unscoped probe).
 */
export async function resolveRemoteProtocolIdentifier<K extends RemoteProtocolIdKind>(
  db: PrismaClient,
  kind: K,
  protocolId: RemoteProtocolIdBytes<NoInfer<K>>,
  authz: RemoteProtocolAuthz,
): Promise<{ sourceId: string }> {
  assertKindAllowed(authz, kind);
  if (protocolId.length !== REMOTE_PROTOCOL_ID_BYTES || isAllZero(protocolId)) {
    throw new RemoteProtocolIdentifierDenied();
  }
  // Runtime kind brand check — fail before DB even if generics were widened.
  let brandedKind: RemoteProtocolIdKind;
  try {
    brandedKind = protocolIdKindOf(protocolId);
  } catch {
    throw new RemoteProtocolIdentifierDenied();
  }
  if (brandedKind !== kind) {
    throw new RemoteProtocolIdentifierDenied();
  }

  const data = loadAuthz(authz);
  const protocolIdBuf = Buffer.from(protocolId);

  // Tenant: constrain the predicate to authorized sources so foreign aliases
  // are an identical scoped miss (no global existence probe).
  if (data.mode === "tenant") {
    const allowed = data.authorizedSourceIds[kind] ?? [];
    if (allowed.length === 0) {
      throw new RemoteProtocolIdentifierDenied();
    }
    const row = await db.remoteProtocolIdentifier.findFirst({
      where: {
        kind,
        protocolId: protocolIdBuf,
        sourceId: { in: [...allowed] },
        retiredAt: null,
      },
    });
    if (!row || row.sourceId === null) {
      throw new RemoteProtocolIdentifierDenied();
    }
    return { sourceId: row.sourceId };
  }

  // System: full authority; exact kind+protocolId lookup.
  const row = await db.remoteProtocolIdentifier.findUnique({
    where: {
      kind_protocolId: { kind, protocolId: protocolIdBuf },
    },
  });
  if (!row || row.retiredAt || row.sourceId === null) {
    throw new RemoteProtocolIdentifierDenied();
  }
  return { sourceId: row.sourceId };
}

/**
 * Retire alias permanently: clear source binding (tombstone), keep protocolId.
 * The protocolId never reassigns; source may later allocate a fresh alias.
 *
 * Pass a transaction client as `db` when composing with source-row deletion in
 * the same Prisma transaction (client has `$transaction`; tx does not).
 */
export async function retireRemoteProtocolIdentifier(
  db: PrismaClient | PrismaTx,
  kind: RemoteProtocolIdKind,
  sourceId: string,
  authz: RemoteProtocolAuthz,
): Promise<void> {
  assertKindAndSourceAuthorized(authz, kind, sourceId);
  const run = async (tx: { remoteProtocolIdentifier: PrismaTx["remoteProtocolIdentifier"] }) => {
    await tx.remoteProtocolIdentifier.updateMany({
      where: { kind, sourceId, retiredAt: null },
      data: { retiredAt: new Date(), sourceId: null },
    });
  };
  if (typeof (db as PrismaClient).$transaction === "function") {
    await (db as PrismaClient).$transaction(async (tx: PrismaTx) => run(tx), {
      isolationLevel: "Serializable",
    });
    return;
  }
  await run(db as PrismaTx);
}

export function protocolIdToWireText(protocolId: Uint8Array): string {
  return encodeProtocolIdBase64Url(protocolId);
}
