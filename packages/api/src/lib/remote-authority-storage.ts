import { canonicalizeRfc8785 } from "@flycockpit/cockpit-protocol";
import {
  type MembershipSnapshot,
  type ObservationLease,
  type PublicAuthorityRing,
  publicAuthorityRingDigest,
  type RemoteAuthorityStatusV1,
  type SigningJournalEntry,
} from "./remote-authority";
import type {
  AuthorityLifecycleRecord,
  AuthorityObservationStore,
  AuthorityRuntimeStore,
  FinalizedAuthorityStatus,
} from "./remote-authority-runtime";

export interface SqlClient {
  $queryRawUnsafe<T = unknown>(query: string, ...values: unknown[]): Promise<T>;
  $executeRawUnsafe(query: string, ...values: unknown[]): Promise<number>;
  $transaction<T>(
    callback: (tx: SqlClient) => Promise<T>,
    options?: { isolationLevel?: "Serializable" },
  ): Promise<T>;
}
export interface RedisClient {
  time(): Promise<Array<string | number>>;
  set(key: string, value: string, mode: "EX", ttl: number): Promise<unknown>;
  keys(pattern: string): Promise<string[]>;
  mget(...keys: string[]): Promise<Array<string | null>>;
}
const text = (value: unknown) => String(value);
export class PostgresAuthorityRuntimeStore implements AuthorityRuntimeStore {
  constructor(private readonly db: SqlClient) {}
  async loadLifecycle(deploymentId: string) {
    const rows = await this.db.$queryRawUnsafe<Array<Record<string, unknown>>>(
        `SELECT "revision","ringDigest","authorityEpoch","currentKid","revokedKidsJson","generation" FROM remote_authority_lifecycle_state WHERE "deploymentId"=$1`,
        deploymentId,
      ),
      row = rows[0];
    if (!row) return null;
    const revoked = JSON.parse(String(row.revokedKidsJson));
    if (!Array.isArray(revoked) || revoked.some((x) => typeof x !== "string"))
      throw new Error("invalid revoked kid state");
    return {
      revision: text(row.revision),
      ringDigest: text(row.ringDigest),
      authorityEpoch: text(row.authorityEpoch),
      currentKid: text(row.currentKid),
      revokedKids: revoked,
      highestStatusGeneration: text(row.generation),
    } satisfies AuthorityLifecycleRecord;
  }
  async loadMembership(deploymentId: string) {
    const rows = await this.db.$queryRawUnsafe<Array<Record<string, unknown>>>(
      `SELECT "membershipGeneration","replicaId","replicaGeneration","state" FROM remote_authority_replica_memberships WHERE "deploymentId"=$1 ORDER BY "replicaId"`,
      deploymentId,
    );
    if (rows.length === 0) return { membershipGeneration: "0", members: [] };
    const generation = text(rows[0]!.membershipGeneration);
    if (rows.some((row) => text(row.membershipGeneration) !== generation))
      throw new Error("inconsistent membership generation");
    return {
      membershipGeneration: generation,
      members: rows.map((row) => ({
        replicaId: text(row.replicaId),
        replicaGeneration: text(row.replicaGeneration),
        state: text(row.state) as "joining" | "required" | "draining",
      })),
    } satisfies MembershipSnapshot;
  }
  async loadPublicRings(deploymentId: string, digests: readonly string[]) {
    if (digests.length === 0) return new Map();
    const rows = await this.db.$queryRawUnsafe<Array<Record<string, unknown>>>(
      `SELECT "ringDigest","canonicalJson" FROM remote_authority_ring_snapshots WHERE "deploymentId"=$1 AND "ringDigest" = ANY($2::text[])`,
      deploymentId,
      [...digests],
    );
    const result = new Map<string, PublicAuthorityRing>();
    for (const row of rows) {
      const ring = JSON.parse(text(row.canonicalJson)) as PublicAuthorityRing,
        digest = text(row.ringDigest);
      if (publicAuthorityRingDigest(ring) !== digest)
        throw new Error("stored ring digest mismatch");
      result.set(digest, ring);
    }
    return result;
  }
  async observePublicRing(deploymentId: string, digest: string, ring: PublicAuthorityRing) {
    if (publicAuthorityRingDigest(ring) !== digest || ring.deploymentId !== deploymentId)
      throw new Error("observed ring mismatch");
    await this.db.$executeRawUnsafe(
      `INSERT INTO remote_authority_ring_snapshots ("deploymentId","ringDigest","revision","authorityEpoch","canonicalJson","observedAt") VALUES ($1,$2,$3::numeric,$4::numeric,$5,NOW()) ON CONFLICT ("deploymentId","ringDigest") DO UPDATE SET "canonicalJson"=EXCLUDED."canonicalJson","observedAt"=NOW() WHERE remote_authority_ring_snapshots."canonicalJson"=EXCLUDED."canonicalJson"`,
      deploymentId,
      digest,
      ring.revision,
      ring.authorityEpoch,
      canonicalizeRfc8785(ring),
    );
  }
  async loadHighestFinalizedStatus(scope: {
    deploymentId: string;
    ringDigest: string;
    authorityEpoch: string;
  }) {
    const rows = await this.db.$queryRawUnsafe<Array<Record<string, unknown>>>(
        `SELECT "compactJws" FROM remote_authority_statuses WHERE "deploymentId"=$1 AND "ringDigest"=$2 AND "authorityEpoch"=$3::numeric AND "finalizedAt" IS NOT NULL ORDER BY "statusGeneration" DESC LIMIT 1`,
        scope.deploymentId,
        scope.ringDigest,
        scope.authorityEpoch,
      ),
      compact = rows[0]?.compactJws;
    if (typeof compact !== "string") return null;
    const part = compact.split(".")[1];
    if (!part) throw new Error("stored status malformed");
    return {
      compactJws: compact,
      status: JSON.parse(
        Buffer.from(part, "base64url").toString("utf8"),
      ) as RemoteAuthorityStatusV1,
    } satisfies FinalizedAuthorityStatus;
  }
  async reserveAndFinalizeStatus(args: {
    deploymentId: string;
    expectedGeneration: string;
    status: RemoteAuthorityStatusV1;
    compactJws: string;
    bodyDigest: string;
  }) {
    return this.db.$transaction(
      async (tx) => {
        const changed = await tx.$executeRawUnsafe(
          `UPDATE remote_authority_lifecycle_state SET "generation"=$3::numeric,"updatedAt"=NOW() WHERE "deploymentId"=$1 AND "generation"=$2::numeric AND "ringDigest"=$4 AND "authorityEpoch"=$5::numeric`,
          args.deploymentId,
          args.expectedGeneration,
          args.status.statusGeneration,
          args.status.ringDigest,
          args.status.authorityEpoch,
        );
        if (changed !== 1) return false;
        const protectedHeader = JSON.parse(
          Buffer.from(args.compactJws.split(".")[0]!, "base64url").toString("utf8"),
        ) as { kid?: unknown };
        if (typeof protectedHeader.kid !== "string") throw new Error("status kid missing");
        await tx.$executeRawUnsafe(
          `INSERT INTO remote_authority_statuses ("deploymentId","statusGeneration","revision","ringDigest","authorityEpoch","kid","compactJws","issuedAt","validUntil","finalizedAt") VALUES ($1,$2::numeric,$3::numeric,$4,$5::numeric,$6,$7,to_timestamp($8::numeric),to_timestamp($9::numeric),NOW())`,
          args.deploymentId,
          args.status.statusGeneration,
          args.status.revision,
          args.status.ringDigest,
          args.status.authorityEpoch,
          protectedHeader.kid,
          args.compactJws,
          args.status.iat,
          args.status.validUntil,
        );
        await tx.$executeRawUnsafe(
          `INSERT INTO remote_authority_control_outbox ("eventId","deploymentId","generation","eventType","payload","createdAt") VALUES ($1,$2,$3::numeric,'authority_status',$4,NOW())`,
          crypto.randomUUID(),
          args.deploymentId,
          args.status.statusGeneration,
          args.compactJws,
        );
        return true;
      },
      { isolationLevel: "Serializable" },
    );
  }
  async reserveMint(args: {
    deploymentId: string;
    mintId: string;
    kid: string;
    signingGeneration: string;
    claimsHash: string;
  }) {
    await this.db.$executeRawUnsafe(
      `INSERT INTO remote_authority_signing_journal ("mintId","deploymentId","signingGeneration","kid","claimsHash","state","providerRequestId","createdAt","updatedAt") SELECT $1,$2,$3::numeric,$4,$5,'reserved',$1,NOW(),NOW() FROM remote_authority_signing_fences WHERE "deploymentId"=$2 AND "kid"=$4 AND "signingGeneration"=$3::numeric AND "state"='open' ON CONFLICT ("mintId") DO NOTHING`,
      args.mintId,
      args.deploymentId,
      args.signingGeneration,
      args.kid,
      args.claimsHash,
    );
    return this.getMint(args.mintId);
  }
  async finalizeMint(args: {
    mintId: string;
    signingGeneration: string;
    claimsHash: string;
    signatureP1363: string;
    compactJws: string;
  }) {
    await this.db.$executeRawUnsafe(
      `UPDATE remote_authority_signing_journal SET "state"='finalized',"signatureP1363"=$4,"compactJws"=$5,"signedAt"=NOW(),"updatedAt"=NOW() WHERE "mintId"=$1 AND "signingGeneration"=$2::numeric AND "claimsHash"=$3 AND "state"='reserved'`,
      args.mintId,
      args.signingGeneration,
      args.claimsHash,
      args.signatureP1363,
      args.compactJws,
    );
    return this.getMint(args.mintId);
  }
  private async getMint(mintId: string) {
    const rows = await this.db.$queryRawUnsafe<Array<Record<string, unknown>>>(
        `SELECT * FROM remote_authority_signing_journal WHERE "mintId"=$1`,
        mintId,
      ),
      row = rows[0];
    if (!row) throw new Error("signing reservation refused");
    return {
      mintId: text(row.mintId),
      signingGeneration: text(row.signingGeneration),
      kid: text(row.kid),
      claimsHash: text(row.claimsHash),
      state: text(row.state),
      signatureP1363: row.signatureP1363 ? text(row.signatureP1363) : undefined,
      compactJws: row.compactJws ? text(row.compactJws) : undefined,
      signedAt: row.signedAt
        ? Math.floor(new Date(row.signedAt as string).getTime() / 1000).toString()
        : undefined,
    } as SigningJournalEntry;
  }
}

export class RedisAuthorityObservationStore implements AuthorityObservationStore {
  constructor(
    private readonly redis: RedisClient,
    private readonly prefix = "remote-authority:lease",
  ) {}
  async redisTime() {
    const [seconds] = await this.redis.time();
    if (seconds === undefined) throw new Error("Redis TIME returned no seconds");
    return String(seconds);
  }
  async publishLease(lease: ObservationLease, ttlSeconds: 30) {
    const key = `${this.prefix}:${lease.deploymentId}:${lease.membershipGeneration}:${lease.replicaId}:${lease.replicaGeneration}:${lease.leaseGeneration}`;
    await this.redis.set(key, canonicalizeRfc8785(lease), "EX", ttlSeconds);
  }
  async listLeases(deploymentId: string, membershipGeneration: string) {
    const keys = await this.redis.keys(`${this.prefix}:${deploymentId}:${membershipGeneration}:*`);
    if (keys.length === 0) return [];
    return (await this.redis.mget(...keys))
      .filter((value): value is string => value !== null)
      .map((value) => JSON.parse(value) as ObservationLease);
  }
}
