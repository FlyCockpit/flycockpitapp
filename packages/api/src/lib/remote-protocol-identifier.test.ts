import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  decodeProtocolIdBase64Url,
  encodeProtocolIdBase64Url,
  protocolIdKindOf,
  REMOTE_PROTOCOL_ID_BYTES,
} from "@flycockpit/cockpit-protocol";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  allocateRemoteProtocolIdentifier,
  protocolIdToWireText,
  RemoteProtocolIdentifierDenied,
  resolveRemoteProtocolIdentifier,
  retireRemoteProtocolIdentifier,
  systemRemoteProtocolAuthz,
  tenantRemoteProtocolAuthz,
} from "./remote-protocol-identifier";

const cryptoState = vi.hoisted(() => ({
  originalRandomBytes: null as null | ((size: number) => Buffer),
}));

vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  cryptoState.originalRandomBytes = actual.randomBytes as (size: number) => Buffer;
  return {
    ...actual,
    randomBytes: vi.fn((size: number) => actual.randomBytes(size)),
  };
});

import { randomBytes } from "node:crypto";

/** flycockpitapp monorepo root (packages/api/src/lib → ../../../..) */
const monorepoRoot = join(fileURLToPath(new URL(".", import.meta.url)), "../../../..");

type Row = {
  kind: string;
  sourceId: string | null;
  protocolId: Buffer;
  retiredAt: Date | null;
};

function asBuf(id: Buffer | Uint8Array): Buffer {
  return Buffer.isBuffer(id) ? id : Buffer.from(id);
}

function protocolIdEqual(a: Buffer | Uint8Array, b: Buffer | Uint8Array): boolean {
  return asBuf(a).equals(asBuf(b));
}

/**
 * In-memory Prisma stand-in.
 * `serializeTransactions: false` allows concurrent overlapping read-then-insert
 * races so same-source unique losers can be exercised.
 */
function makeFakeDb(options?: { serializeTransactions?: boolean }) {
  const rows: Row[] = [];
  let lock: Promise<void> = Promise.resolve();
  const serialize = options?.serializeTransactions !== false;

  const withLock = async <T>(fn: () => Promise<T>): Promise<T> => {
    if (!serialize) {
      return fn();
    }
    const prev = lock;
    let release!: () => void;
    lock = new Promise<void>((r) => {
      release = r;
    });
    await prev;
    try {
      return await fn();
    } finally {
      release();
    }
  };

  const remoteProtocolIdentifier = {
    findUnique: async ({
      where,
    }: {
      where:
        | { kind_sourceId: { kind: string; sourceId: string } }
        | { kind_protocolId: { kind: string; protocolId: Buffer | Uint8Array } };
    }) => {
      if ("kind_sourceId" in where) {
        const { kind, sourceId } = where.kind_sourceId;
        return (
          rows.find((r) => r.kind === kind && r.sourceId !== null && r.sourceId === sourceId) ??
          null
        );
      }
      const { kind, protocolId } = where.kind_protocolId;
      return rows.find((r) => r.kind === kind && protocolIdEqual(r.protocolId, protocolId)) ?? null;
    },
    findFirst: async ({
      where,
    }: {
      where: {
        kind: string;
        protocolId: Buffer | Uint8Array;
        sourceId: { in: string[] };
        retiredAt: null;
      };
    }) => {
      return (
        rows.find(
          (r) =>
            r.kind === where.kind &&
            protocolIdEqual(r.protocolId, where.protocolId) &&
            r.sourceId !== null &&
            where.sourceId.in.includes(r.sourceId) &&
            r.retiredAt === null,
        ) ?? null
      );
    },
    create: async ({
      data,
    }: {
      data: { kind: string; sourceId: string | null; protocolId: Buffer | Uint8Array };
    }) => {
      const protocolId = asBuf(data.protocolId);
      if (
        data.sourceId !== null &&
        rows.some((r) => r.kind === data.kind && r.sourceId === data.sourceId)
      ) {
        throw Object.assign(new Error("Unique constraint failed on kind_sourceId"), {
          code: "P2002",
          meta: { target: ["kind", "sourceId"] },
        });
      }
      if (rows.some((r) => r.kind === data.kind && protocolIdEqual(r.protocolId, protocolId))) {
        throw Object.assign(new Error("Unique constraint failed on kind_protocolId"), {
          code: "P2002",
          meta: { target: ["kind", "protocolId"] },
        });
      }
      const row: Row = {
        kind: data.kind,
        sourceId: data.sourceId,
        protocolId,
        retiredAt: null,
      };
      rows.push(row);
      return row;
    },
    updateMany: async ({
      where,
      data,
    }: {
      where: { kind: string; sourceId: string; retiredAt: null };
      data: { retiredAt: Date; sourceId: null };
    }) => {
      let count = 0;
      for (const r of rows) {
        if (r.kind === where.kind && r.sourceId === where.sourceId && r.retiredAt === null) {
          r.retiredAt = data.retiredAt;
          r.sourceId = null;
          count++;
        }
      }
      return { count };
    },
  };

  const db = {
    $transaction: async (fn: (tx: typeof db) => Promise<unknown>) => withLock(async () => fn(db)),
    remoteProtocolIdentifier,
  };
  return { db: db as never, rows };
}

describe("remote_protocol_identifier_allocation_race", () => {
  it("allocates 16-byte CSPRNG ids idempotently for the same source", async () => {
    const { db, rows } = makeFakeDb();
    const authz = systemRemoteProtocolAuthz();
    const a = await allocateRemoteProtocolIdentifier(db, "tenant", "src-1", authz);
    const b = await allocateRemoteProtocolIdentifier(db, "tenant", "src-1", authz);
    expect(a.length).toBe(REMOTE_PROTOCOL_ID_BYTES);
    expect(Array.from(a)).toEqual(Array.from(b));
    expect(protocolIdKindOf(a)).toBe("tenant");
    expect(rows).toHaveLength(1);
    expect(rows[0]!.retiredAt).toBeNull();
    expect(a.every((b) => b === 0)).toBe(false);
  });

  it("concurrent same-source allocation yields one winner (overlapping races)", async () => {
    // Non-serialized transactions: concurrent creates race on (kind, sourceId).
    const { db, rows } = makeFakeDb({ serializeTransactions: false });
    const authz = systemRemoteProtocolAuthz();
    const settled = await Promise.all(
      Array.from({ length: 16 }, () =>
        allocateRemoteProtocolIdentifier(db, "tenant", "race-src", authz),
      ),
    );
    expect(rows.filter((r) => r.sourceId === "race-src")).toHaveLength(1);
    const first = Array.from(settled[0]!);
    for (const id of settled) {
      expect(Array.from(id)).toEqual(first);
    }
  });

  afterEach(() => {
    vi.mocked(randomBytes).mockImplementation((size: number) =>
      cryptoState.originalRandomBytes!(size),
    );
  });

  it("retries protocolId collision with fresh entropy and keeps source uniqueness", async () => {
    const { db, rows } = makeFakeDb();
    const authz = systemRemoteProtocolAuthz();
    const existing = await allocateRemoteProtocolIdentifier(db, "tenant", "taken-src", authz);
    const colliding = Buffer.from(existing);
    let calls = 0;
    vi.mocked(randomBytes).mockImplementation((size: number) => {
      calls++;
      if (calls === 1) return Buffer.from(colliding) as never;
      const fresh = Buffer.alloc(size);
      fresh[0] = 0x7e;
      fresh[15] = 0x81;
      return fresh as never;
    });
    const allocated = await allocateRemoteProtocolIdentifier(db, "tenant", "new-src", authz);
    expect(calls).toBeGreaterThanOrEqual(2);
    expect(Buffer.from(allocated).equals(colliding)).toBe(false);
    expect(rows).toHaveLength(2);
  });

  it("rejects all-zero entropy without persisting", async () => {
    const { db, rows } = makeFakeDb();
    vi.mocked(randomBytes).mockImplementation((size: number) => Buffer.alloc(size) as never);
    await expect(
      allocateRemoteProtocolIdentifier(db, "tenant", "z", systemRemoteProtocolAuthz()),
    ).rejects.toThrow(/all-zero|exhausted/);
    expect(rows).toHaveLength(0);
  });

  it("keeps distinct sources distinct", async () => {
    const { db, rows } = makeFakeDb();
    const authz = systemRemoteProtocolAuthz();
    const a = await allocateRemoteProtocolIdentifier(db, "tenant", "src-a", authz);
    const b = await allocateRemoteProtocolIdentifier(db, "tenant", "src-b", authz);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    expect(rows).toHaveLength(2);
  });

  it("retirement clears source binding; old protocolId never resolves; no reuse", async () => {
    const { db, rows } = makeFakeDb();
    const authz = systemRemoteProtocolAuthz();
    const id = await allocateRemoteProtocolIdentifier(db, "account", "acc-1", authz);
    await retireRemoteProtocolIdentifier(db, "account", "acc-1", authz);
    expect(rows[0]!.sourceId).toBeNull();
    expect(rows[0]!.retiredAt).not.toBeNull();
    await expect(resolveRemoteProtocolIdentifier(db, "account", id, authz)).rejects.toBeInstanceOf(
      RemoteProtocolIdentifierDenied,
    );
    // Fresh alias for same source is a new protocolId; old tombstone never reassigns.
    const fresh = await allocateRemoteProtocolIdentifier(db, "account", "acc-1", authz);
    expect(Buffer.from(fresh).equals(Buffer.from(id))).toBe(false);
    await expect(resolveRemoteProtocolIdentifier(db, "account", fresh, authz)).resolves.toEqual({
      sourceId: "acc-1",
    });
    expect(rows.filter((r) => r.retiredAt !== null)).toHaveLength(1);
  });
});

describe("remote_protocol_identifier_authorization_matrix", () => {
  it("denies unknown/unauthorized/cross-kind with identical errors", async () => {
    const { db } = makeFakeDb();
    const id = await allocateRemoteProtocolIdentifier(
      db,
      "tenant",
      "tenant-a",
      systemRemoteProtocolAuthz(),
    );
    const e1 = await resolveRemoteProtocolIdentifier(
      db,
      "tenant",
      id,
      tenantRemoteProtocolAuthz({
        tenantSourceId: "tenant-b",
        allowedKinds: ["tenant"],
        authorizedSourceIds: {},
      }),
    ).catch((e: unknown) => e);
    const { tagProtocolIdBytes } = await import("@flycockpit/cockpit-protocol");
    const badBytes = new Uint8Array(16).fill(9);
    badBytes[0] = 0x42;
    const unknownTagged = tagProtocolIdBytes("tenant", badBytes);
    const eUnknown = await resolveRemoteProtocolIdentifier(
      db,
      "tenant",
      unknownTagged,
      systemRemoteProtocolAuthz(),
    ).catch((e: unknown) => e);
    const e3 = await resolveRemoteProtocolIdentifier(
      db,
      "account",
      tagProtocolIdBytes("account", new Uint8Array(id)),
      systemRemoteProtocolAuthz(),
    ).catch((e: unknown) => e);

    expect(e1).toBeInstanceOf(RemoteProtocolIdentifierDenied);
    expect(eUnknown).toBeInstanceOf(RemoteProtocolIdentifierDenied);
    expect(e3).toBeInstanceOf(RemoteProtocolIdentifierDenied);
    expect((e1 as Error).message).toBe((eUnknown as Error).message);
    expect((eUnknown as Error).message).toBe((e3 as Error).message);
  });

  it("rejects kind not on allow-list before lookup", async () => {
    const { db } = makeFakeDb();
    await expect(
      allocateRemoteProtocolIdentifier(
        db,
        "project",
        "p1",
        tenantRemoteProtocolAuthz({
          tenantSourceId: "t1",
          allowedKinds: ["tenant"],
          authorizedSourceIds: {},
        }),
      ),
    ).rejects.toBeInstanceOf(RemoteProtocolIdentifierDenied);
  });

  it("tenant capability cannot allocate or resolve foreign account aliases", async () => {
    const { db } = makeFakeDb();
    const system = systemRemoteProtocolAuthz();
    const accountId = await allocateRemoteProtocolIdentifier(db, "account", "acc-foreign", system);
    const tenantA = tenantRemoteProtocolAuthz({
      tenantSourceId: "tenant-a",
      allowedKinds: ["tenant", "account"],
      authorizedSourceIds: { account: ["acc-own"] },
    });
    await expect(
      allocateRemoteProtocolIdentifier(db, "account", "acc-foreign", tenantA),
    ).rejects.toBeInstanceOf(RemoteProtocolIdentifierDenied);
    await expect(
      resolveRemoteProtocolIdentifier(db, "account", accountId, tenantA),
    ).rejects.toBeInstanceOf(RemoteProtocolIdentifierDenied);
    const own = await allocateRemoteProtocolIdentifier(db, "account", "acc-own", tenantA);
    await expect(resolveRemoteProtocolIdentifier(db, "account", own, tenantA)).resolves.toEqual({
      sourceId: "acc-own",
    });
  });

  it("tenant capability ignores injected foreign tenant grants", async () => {
    const { db } = makeFakeDb();
    const system = systemRemoteProtocolAuthz();
    const foreign = await allocateRemoteProtocolIdentifier(db, "tenant", "tenant-b", system);
    const tenantA = tenantRemoteProtocolAuthz({
      tenantSourceId: "tenant-a",
      allowedKinds: ["tenant"],
      // Attempt to inject foreign tenant into grants — factory must overwrite.
      authorizedSourceIds: { tenant: ["tenant-b", "tenant-c"] },
    });
    await expect(
      resolveRemoteProtocolIdentifier(db, "tenant", foreign, tenantA),
    ).rejects.toBeInstanceOf(RemoteProtocolIdentifierDenied);
    const own = await allocateRemoteProtocolIdentifier(db, "tenant", "tenant-a", tenantA);
    await expect(resolveRemoteProtocolIdentifier(db, "tenant", own, tenantA)).resolves.toEqual({
      sourceId: "tenant-a",
    });
  });

  it("rejects forgeable authz tokens; grants are not on the token surface", async () => {
    const { db } = makeFakeDb();
    const brandless = {
      mode: "system",
      allowedKinds: ["tenant"],
      authorizedSourceIds: new Map(),
    } as never;
    await expect(
      allocateRemoteProtocolIdentifier(db, "tenant", "x", brandless),
    ).rejects.toBeInstanceOf(RemoteProtocolIdentifierDenied);

    const forged = {
      [Symbol.for("flycockpit.RemoteProtocolAuthz")]: true,
      mode: "system",
      allowedKinds: ["tenant", "account", "instance", "project"],
      authorizedSourceIds: new Map(),
    } as never;
    await expect(
      allocateRemoteProtocolIdentifier(db, "tenant", "x", forged),
    ).rejects.toBeInstanceOf(RemoteProtocolIdentifierDenied);

    // Issued capability is opaque + frozen; no mutable grant collections on the token.
    const cap = tenantRemoteProtocolAuthz({
      tenantSourceId: "t1",
      allowedKinds: ["tenant", "account"],
      authorizedSourceIds: { account: ["acc-own"] },
    });
    expect(() => {
      (cap as { mode: string }).mode = "system";
    }).toThrow();
    expect(Object.keys(cap)).toEqual([]);
    expect("authorizedSourceIds" in cap).toBe(false);
    expect("allowedKinds" in cap).toBe(false);

    // Kind-confused resolve (wrong brand) fails before DB.
    const system = systemRemoteProtocolAuthz();
    const accountId = await allocateRemoteProtocolIdentifier(db, "account", "acc-own", system);
    await expect(
      resolveRemoteProtocolIdentifier(db, "tenant", accountId as never, system),
    ).rejects.toBeInstanceOf(RemoteProtocolIdentifierDenied);
  });

  it("exports no enumeration/list/probe surface", async () => {
    const mod = await import("./remote-protocol-identifier");
    const keys = Object.keys(mod).sort();
    expect(keys).not.toContain("listRemoteProtocolIdentifiers");
    expect(keys).not.toContain("searchRemoteProtocolIdentifiers");
    expect(keys).not.toContain("probeRemoteProtocolIdentifier");
    expect(keys).toEqual(
      expect.arrayContaining([
        "allocateRemoteProtocolIdentifier",
        "resolveRemoteProtocolIdentifier",
        "retireRemoteProtocolIdentifier",
        "protocolIdToWireText",
        "systemRemoteProtocolAuthz",
        "tenantRemoteProtocolAuthz",
        "RemoteProtocolIdentifierDenied",
      ]),
    );
  });
});

describe("remote_protocol_identifier_no_raw_cuid_wire", () => {
  it("protocol wire text never embeds cuid source shapes", () => {
    const bytes = new Uint8Array(REMOTE_PROTOCOL_ID_BYTES);
    bytes[0] = 0xab;
    bytes[15] = 0xcd;
    const wire = protocolIdToWireText(bytes);
    expect(wire.startsWith("cl")).toBe(false);
    expect(wire.includes("cuid")).toBe(false);
    expect(decodeProtocolIdBase64Url(wire)).toEqual(bytes);
    expect(encodeProtocolIdBase64Url(bytes)).toBe(wire);
  });

  it("scans remote wire surfaces for cuid→protocolId coercion and sourceId leakage", () => {
    const scanDirs = [
      "packages/cockpit-protocol/src",
      "packages/relay-protocol/src",
      "packages/api/src/lib",
      "packages/api/src/enterprise",
      "crates/cockpit-proto/src",
    ];
    const mappingAllow = new Set([
      "packages/api/src/lib/remote-protocol-identifier.ts",
      "packages/api/src/lib/remote-protocol-identifier.test.ts",
      "packages/db/prisma/schema/remote-protocol.prisma",
    ]);
    const coercion =
      /protocolId\s*[:=]\s*.*cuid|cuid\s*\(.*\)\s*.*protocolId|Buffer\.from\(\s*[^)]*cuid|protocol_id\s*=\s*.*cuid/i;
    // sourceId must not appear in denial Error messages / console / wire DTO field names
    // outside mapping module.
    const sourceIdLeak =
      /console\.(log|info|warn|error|debug)\([^)]*sourceId|throw new Error\([^)]*sourceId|`[^`]*sourceId[^`]*`|"sourceId"\s*:/i;
    const files: string[] = [];
    const walk = (rel: string) => {
      const abs = join(monorepoRoot, rel);
      let st: ReturnType<typeof statSync>;
      try {
        st = statSync(abs);
      } catch {
        return;
      }
      if (st.isDirectory()) {
        for (const name of readdirSync(abs)) {
          if (name === "node_modules" || name === "generated" || name === "dist") continue;
          walk(join(rel, name));
        }
        return;
      }
      if (!/\.(ts|tsx|rs|prisma)$/.test(rel)) return;
      files.push(rel);
    };
    for (const d of scanDirs) walk(d);
    expect(files.length).toBeGreaterThan(10);

    const coercionHits: string[] = [];
    const leakHits: string[] = [];
    for (const rel of files) {
      if (mappingAllow.has(rel) || rel.endsWith(".test.ts") || rel.endsWith("_test.rs")) continue;
      const text = readFileSync(join(monorepoRoot, rel), "utf8");
      if (coercion.test(text)) {
        coercionHits.push(rel);
      }
      // Foundation mapping owns sourceId fields; codecs must not.
      if (rel.includes("remote-protocol-id") && sourceIdLeak.test(text)) {
        leakHits.push(rel);
      }
    }
    expect(coercionHits).toEqual([]);
    expect(leakHits).toEqual([]);

    const mapping = readFileSync(
      join(monorepoRoot, "packages/api/src/lib/remote-protocol-identifier.ts"),
      "utf8",
    );
    expect(mapping).toContain("sourceId");
    expect(mapping).toMatch(/remote protocol identifier denied/);
    // Denial message must not interpolate sourceId.
    expect(mapping).not.toMatch(/denied.*\$\{.*sourceId|sourceId.*denied/);
    expect(mapping).not.toMatch(/console\.(log|info|warn|error).*sourceId/);

    const codec = readFileSync(
      join(monorepoRoot, "packages/cockpit-protocol/src/remote-protocol-id.ts"),
      "utf8",
    );
    expect(codec).toContain("all-zero");
    expect(codec).not.toMatch(/cuid\s*\(/);
    // Foundation codec module is the sole owner of CanonicalU64DecimalStringV1;
    // enterprise Int seq is domain storage (not remote-protocol u64 wire).
    expect(codec).toContain("CanonicalU64DecimalStringV1");
    expect(codec).toContain("parseCanonicalU64DecimalString");
  });
});
