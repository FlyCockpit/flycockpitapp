import { canonicalizeRfc8785 } from "@flycockpit/cockpit-protocol";
import {
  type MembershipSnapshot,
  type ObservationLease,
  type PublicAuthorityRing,
  publicAuthorityRingDigest,
  type RemoteAuthorityStatusV1,
  type SigningJournalEntry,
  validateFrozenSigningJournalProof,
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
  scan(
    cursor: string,
    matchToken: "MATCH",
    pattern: string,
    countToken: "COUNT",
    count: number,
  ): Promise<[string, string[]]>;
  get(key: string): Promise<string | null>;
  incr(key: string): Promise<number>;
  eval(script: string, numberOfKeys: number, ...args: string[]): Promise<unknown>;
}
const text = (value: unknown) => String(value);
export class PostgresAuthorityRuntimeStore implements AuthorityRuntimeStore {
  constructor(private readonly db: SqlClient) {}
  async bootstrapAuthority(args: {
    deploymentId: string;
    replicaId: string;
    ring: PublicAuthorityRing;
    digest: string;
  }) {
    await this.db.$transaction(
      async (tx) => {
        const inserted = await tx.$executeRawUnsafe(
          `INSERT INTO remote_authority_lifecycle_state ("deploymentId","revision","ringDigest","authorityEpoch","currentKid","revokedKidsJson","generation","updatedAt") VALUES ($1,$2::numeric,$3,$4::numeric,$5,'[]',0,NOW()) ON CONFLICT ("deploymentId") DO NOTHING`,
          args.deploymentId,
          args.ring.revision,
          args.digest,
          args.ring.authorityEpoch,
          args.ring.currentKid,
        );
        const members = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "membershipGeneration","replicaId","replicaGeneration","state" FROM remote_authority_replica_memberships WHERE "deploymentId"=$1 FOR UPDATE`,
          args.deploymentId,
        );
        const existingMember = members.find((member) => member.replicaId === args.replicaId);
        if (!existingMember) {
          const generation = members.length === 0 ? "1" : text(members[0]?.membershipGeneration);
          await tx.$executeRawUnsafe(
            `INSERT INTO remote_authority_replica_memberships ("deploymentId","membershipGeneration","replicaId","replicaGeneration","state","updatedAt") VALUES ($1,$2::numeric,$3,1,$4,NOW())`,
            args.deploymentId,
            generation,
            args.replicaId,
            members.length === 0 ? "required" : "joining",
          );
        } else if (existingMember.state === "draining") {
          const nextMembership = (
              BigInt(text(existingMember.membershipGeneration)) + 1n
            ).toString(),
            nextReplica = (BigInt(text(existingMember.replicaGeneration)) + 1n).toString();
          await tx.$executeRawUnsafe(
            `UPDATE remote_authority_replica_memberships SET "membershipGeneration"=$2::numeric,"replicaGeneration"=CASE WHEN "replicaId"=$3 THEN $4::numeric ELSE "replicaGeneration" END,"state"=CASE WHEN "replicaId"=$3 THEN 'joining'::"RemoteAuthorityReplicaState" ELSE "state" END,"updatedAt"=NOW() WHERE "deploymentId"=$1`,
            args.deploymentId,
            nextMembership,
            args.replicaId,
            nextReplica,
          );
        }
        if (inserted === 1)
          await tx.$executeRawUnsafe(
            `INSERT INTO remote_authority_signing_fences ("deploymentId","kid","signingGeneration","state","updatedAt") VALUES ($1,$2,$3::numeric,'open',NOW()) ON CONFLICT ("deploymentId","kid","signingGeneration") DO NOTHING`,
            args.deploymentId,
            args.ring.currentKid,
            args.ring.authorityEpoch,
          );
      },
      { isolationLevel: "Serializable" },
    );
  }
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
  async promoteJoiningReplica(deploymentId: string, replicaId: string) {
    return this.db.$transaction(
      async (tx) => {
        const rows = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "membershipGeneration","state" FROM remote_authority_replica_memberships WHERE "deploymentId"=$1 AND "replicaId"=$2 FOR UPDATE`,
          deploymentId,
          replicaId,
        );
        if (rows[0]?.state !== "joining") return false;
        const next = (BigInt(text(rows[0]?.membershipGeneration)) + 1n).toString();
        await tx.$executeRawUnsafe(
          `UPDATE remote_authority_replica_memberships SET "membershipGeneration"=$2::numeric,"state"=CASE WHEN "replicaId"=$3 THEN 'required'::"RemoteAuthorityReplicaState" ELSE "state" END,"updatedAt"=NOW() WHERE "deploymentId"=$1`,
          deploymentId,
          next,
          replicaId,
        );
        return true;
      },
      { isolationLevel: "Serializable" },
    );
  }
  async drainReplica(deploymentId: string, replicaId: string) {
    return this.db.$transaction(
      async (tx) => {
        const rows = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "membershipGeneration","state" FROM remote_authority_replica_memberships WHERE "deploymentId"=$1 AND "replicaId"=$2 FOR UPDATE`,
          deploymentId,
          replicaId,
        );
        if (rows[0]?.state !== "required") return false;
        const next = (BigInt(text(rows[0]?.membershipGeneration)) + 1n).toString();
        await tx.$executeRawUnsafe(
          `UPDATE remote_authority_replica_memberships SET "membershipGeneration"=$2::numeric,"state"=CASE WHEN "replicaId"=$3 THEN 'draining'::"RemoteAuthorityReplicaState" ELSE "state" END,"updatedAt"=NOW() WHERE "deploymentId"=$1`,
          deploymentId,
          next,
          replicaId,
        );
        return true;
      },
      { isolationLevel: "Serializable" },
    );
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
          `UPDATE remote_authority_lifecycle_state SET "generation"=$3::numeric,"updatedAt"=NOW() WHERE "deploymentId"=$1 AND "generation"=$2::numeric AND "ringDigest"=$4 AND "authorityEpoch"=$5::numeric AND NOT EXISTS (SELECT 1 FROM remote_authority_lifecycle_transitions WHERE "deploymentId"=$1 AND ("state"='reserved' OR "state"='status_signed'))`,
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
  async acquireStatusLease(args: {
    deploymentId: string;
    replicaId: string;
    leaseGeneration: string;
  }) {
    const changed = await this.db.$executeRawUnsafe(
      `INSERT INTO remote_authority_status_leases ("deploymentId","holderReplicaId","leaseGeneration","expiresAt","updatedAt") VALUES ($1,$2,$3::numeric,NOW()+INTERVAL '20 seconds',NOW()) ON CONFLICT ("deploymentId") DO UPDATE SET "holderReplicaId"=EXCLUDED."holderReplicaId","leaseGeneration"=EXCLUDED."leaseGeneration","expiresAt"=EXCLUDED."expiresAt","updatedAt"=NOW() WHERE remote_authority_status_leases."expiresAt"<=NOW() OR (remote_authority_status_leases."holderReplicaId"=$2 AND remote_authority_status_leases."leaseGeneration"=$3::numeric)`,
      args.deploymentId,
      args.replicaId,
      args.leaseGeneration,
    );
    return changed === 1;
  }
  async prepareLifecycleTransition(args: {
    transitionId: string;
    deploymentId: string;
    from: AuthorityLifecycleRecord;
    to: PublicAuthorityRing;
    toDigest: string;
    statusGeneration: string;
    statusBodyDigest: string;
    signerKid: string;
  }) {
    return this.db.$transaction(
      async (tx) => {
        const lifecycle = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT * FROM remote_authority_lifecycle_state WHERE "deploymentId"=$1 FOR UPDATE`,
          args.deploymentId,
        );
        const row = lifecycle[0];
        if (
          !row ||
          text(row.ringDigest) !== args.from.ringDigest ||
          text(row.authorityEpoch) !== args.from.authorityEpoch
        )
          return false;
        await tx.$executeRawUnsafe(
          `INSERT INTO remote_authority_lifecycle_transitions ("transitionId","deploymentId","state","fromRevision","toRevision","fromDigest","toDigest","fromAuthorityEpoch","toAuthorityEpoch","fromCurrentKid","toCurrentKid","statusGeneration","statusBodyDigest","signingGeneration","signerKid","createdAt","updatedAt") VALUES ($1,$2,'reserved',$3::numeric,$4::numeric,$5,$6,$7::numeric,$8::numeric,$9,$10,$11::numeric,$12,$8::numeric,$13,NOW(),NOW()) ON CONFLICT ("transitionId") DO NOTHING`,
          args.transitionId,
          args.deploymentId,
          args.from.revision,
          args.to.revision,
          args.from.ringDigest,
          args.toDigest,
          args.from.authorityEpoch,
          args.to.authorityEpoch,
          args.from.currentKid,
          args.to.currentKid,
          args.statusGeneration,
          args.statusBodyDigest,
          args.signerKid,
        );
        const transition = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "statusCompactJws" FROM remote_authority_lifecycle_transitions WHERE "transitionId"=$1`,
          args.transitionId,
        );
        return typeof transition[0]?.statusCompactJws === "string"
          ? transition[0].statusCompactJws
          : true;
      },
      { isolationLevel: "Serializable" },
    );
  }
  async markTransitionStatusSigned(transitionId: string, compactJws: string) {
    const changed = await this.db.$executeRawUnsafe(
      `UPDATE remote_authority_lifecycle_transitions SET "state"='status_signed',"statusCompactJws"=$2,"updatedAt"=NOW() WHERE "transitionId"=$1 AND ("state"='reserved' OR ("state"='status_signed' AND "statusCompactJws"=$2))`,
      transitionId,
      compactJws,
    );
    return changed === 1;
  }
  async commitLifecycleTransition(args: {
    transitionId: string;
    deploymentId: string;
    status: RemoteAuthorityStatusV1;
    compactJws: string;
    signerKid: string;
    revokedKids: string[];
  }) {
    return this.db.$transaction(
      async (tx) => {
        const changed = await tx.$executeRawUnsafe(
          `UPDATE remote_authority_lifecycle_state l SET "revision"=t."toRevision","ringDigest"=t."toDigest","authorityEpoch"=t."toAuthorityEpoch","currentKid"=t."toCurrentKid","revokedKidsJson"=$3,"generation"=t."statusGeneration","updatedAt"=NOW() FROM remote_authority_lifecycle_transitions t WHERE t."transitionId"=$1 AND t."deploymentId"=$2 AND t."state"='status_signed' AND t."statusCompactJws"=$4 AND l."deploymentId"=t."deploymentId" AND l."revision"=t."fromRevision" AND l."ringDigest"=t."fromDigest" AND l."authorityEpoch"=t."fromAuthorityEpoch"`,
          args.transitionId,
          args.deploymentId,
          JSON.stringify(args.revokedKids),
          args.compactJws,
        );
        if (changed !== 1) return false;
        await tx.$executeRawUnsafe(
          `INSERT INTO remote_authority_statuses ("deploymentId","statusGeneration","revision","ringDigest","authorityEpoch","kid","compactJws","issuedAt","validUntil","finalizedAt") VALUES ($1,$2::numeric,$3::numeric,$4,$5::numeric,$6,$7,to_timestamp($8::numeric),to_timestamp($9::numeric),NOW()) ON CONFLICT ("deploymentId","statusGeneration") DO NOTHING`,
          args.deploymentId,
          args.status.statusGeneration,
          args.status.revision,
          args.status.ringDigest,
          args.status.authorityEpoch,
          args.signerKid,
          args.compactJws,
          args.status.iat,
          args.status.validUntil,
        );
        await tx.$executeRawUnsafe(
          `UPDATE remote_authority_lifecycle_transitions SET "state"='committed',"updatedAt"=NOW() WHERE "transitionId"=$1`,
          args.transitionId,
        );
        await tx.$executeRawUnsafe(
          `INSERT INTO remote_authority_control_outbox ("eventId","deploymentId","generation","eventType","payload","createdAt") VALUES ($1,$2,$3::numeric,'authority_lifecycle',$4,NOW()) ON CONFLICT ("deploymentId","generation","eventType") DO NOTHING`,
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
  async ensureOpenSigningFence(args: {
    deploymentId: string;
    kid: string;
    signingGeneration: string;
  }) {
    return this.db.$transaction(
      async (tx) => {
        const existing = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "state","signingGeneration" FROM remote_authority_signing_fences WHERE "deploymentId"=$1 AND "kid"=$2 AND "signingGeneration"=$3::numeric FOR UPDATE`,
          args.deploymentId,
          args.kid,
          args.signingGeneration,
        );
        if (
          existing[0]?.state === "open" &&
          text(existing[0]?.signingGeneration) === args.signingGeneration
        )
          return true;
        const lifecycle = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "authorityEpoch","currentKid" FROM remote_authority_lifecycle_state WHERE "deploymentId"=$1 FOR UPDATE`,
          args.deploymentId,
        );
        if (
          text(lifecycle[0]?.authorityEpoch) !== args.signingGeneration ||
          lifecycle[0]?.currentKid !== args.kid
        )
          return false;
        await tx.$executeRawUnsafe(
          `INSERT INTO remote_authority_signing_fences ("deploymentId","kid","signingGeneration","state","updatedAt") VALUES ($1,$2,$3::numeric,'open',NOW()) ON CONFLICT ("deploymentId","kid","signingGeneration") DO NOTHING`,
          args.deploymentId,
          args.kid,
          args.signingGeneration,
        );
        const fence = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "state","signingGeneration" FROM remote_authority_signing_fences WHERE "deploymentId"=$1 AND "kid"=$2 AND "signingGeneration"=$3::numeric`,
          args.deploymentId,
          args.kid,
          args.signingGeneration,
        );
        return (
          fence[0]?.state === "open" && text(fence[0]?.signingGeneration) === args.signingGeneration
        );
      },
      { isolationLevel: "Serializable" },
    );
  }
  async closeAndFreezeSigningFence(deploymentId: string, kid: string) {
    return this.db.$transaction(
      async (tx) => {
        await tx.$executeRawUnsafe(
          `UPDATE remote_authority_signing_fences SET "state"='closing',"updatedAt"=NOW() WHERE "deploymentId"=$1 AND "kid"=$2 AND "state"='open'`,
          deploymentId,
          kid,
        );
        // The in-process file provider cannot complete work after its process dies: a
        // durable reservation with no recorded signature is therefore confirmed-not-started.
        await tx.$executeRawUnsafe(
          `UPDATE remote_authority_signing_journal SET "state"='aborted',"updatedAt"=NOW() WHERE "deploymentId"=$1 AND "kid"=$2 AND "state"='reserved'`,
          deploymentId,
          kid,
        );
        await tx.$executeRawUnsafe(
          `UPDATE remote_authority_signing_journal SET "state"='finalized',"signedAt"=NOW(),"updatedAt"=NOW() WHERE "deploymentId"=$1 AND "kid"=$2 AND "state"='signed'`,
          deploymentId,
          kid,
        );
        const pending = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT 1 FROM remote_authority_signing_journal WHERE "deploymentId"=$1 AND "kid"=$2 AND ("state"='reserved' OR "state"='signed') LIMIT 1 FOR UPDATE`,
          deploymentId,
          kid,
        );
        if (pending.length !== 0) return false;
        await tx.$executeRawUnsafe(
          `UPDATE remote_authority_signing_fences SET "state"='frozen',"cutoff"=COALESCE((SELECT MAX("signedAt") FROM remote_authority_signing_journal WHERE "deploymentId"=$1 AND "kid"=$2 AND "state"='finalized'),NOW()),"updatedAt"=NOW() WHERE "deploymentId"=$1 AND "kid"=$2 AND "state"='closing'`,
          deploymentId,
          kid,
        );
        return true;
      },
      { isolationLevel: "Serializable" },
    );
  }
  async loadFrozenSigningJournalProof(deploymentId: string, kid: string) {
    const fences = await this.db.$queryRawUnsafe<Array<Record<string, unknown>>>(
        `SELECT "signingGeneration","state","cutoff","updatedAt" FROM remote_authority_signing_fences WHERE "deploymentId"=$1 AND "kid"=$2 AND "state"='frozen' ORDER BY "signingGeneration" DESC LIMIT 1`,
        deploymentId,
        kid,
      ),
      fence = fences[0];
    if (fence?.state !== "frozen" || !fence.cutoff) throw new Error("signing fence is not frozen");
    const rows = await this.db.$queryRawUnsafe<Array<Record<string, unknown>>>(
      `SELECT "mintId","state","signedAt" FROM remote_authority_signing_journal WHERE "deploymentId"=$1 AND "kid"=$2 ORDER BY "mintId"`,
      deploymentId,
      kid,
    );
    const seconds = (value: unknown) =>
      Math.floor(new Date(value as string).getTime() / 1000).toString();
    return validateFrozenSigningJournalProof(
      {
        schemaVersion: 1,
        deploymentId,
        kid,
        signingGeneration: text(fence.signingGeneration),
        state: "frozen",
        cutoff: seconds(fence.cutoff),
        frozenAt: seconds(fence.updatedAt),
        rows: rows.map((row) => ({
          mintId: text(row.mintId),
          state: text(row.state),
          signedAt: row.signedAt ? seconds(row.signedAt) : null,
        })),
      },
      { deploymentId, kid },
    );
  }
  async finalizeMint(args: {
    mintId: string;
    signingGeneration: string;
    claimsHash: string;
    signatureP1363: string;
    compactJws: string;
  }) {
    await this.db.$transaction(
      async (tx) => {
        await tx.$executeRawUnsafe(
          `UPDATE remote_authority_signing_journal SET "state"='signed',"signatureP1363"=$4,"compactJws"=$5,"updatedAt"=NOW() WHERE "mintId"=$1 AND "signingGeneration"=$2::numeric AND "claimsHash"=$3 AND "state"='reserved'`,
          args.mintId,
          args.signingGeneration,
          args.claimsHash,
          args.signatureP1363,
          args.compactJws,
        );
        await tx.$executeRawUnsafe(
          `UPDATE remote_authority_signing_journal j SET "state"='finalized',"signedAt"=NOW(),"updatedAt"=NOW() FROM remote_authority_signing_fences f WHERE j."mintId"=$1 AND j."signingGeneration"=$2::numeric AND j."claimsHash"=$3 AND j."state"='signed' AND f."deploymentId"=j."deploymentId" AND f."kid"=j."kid" AND f."signingGeneration"=j."signingGeneration" AND (f."state"='open' OR f."state"='closing')`,
          args.mintId,
          args.signingGeneration,
          args.claimsHash,
        );
      },
      { isolationLevel: "Serializable" },
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
      deploymentId: text(row.deploymentId),
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
  async nextLeaseGeneration(deploymentId: string, replicaId: string) {
    return String(await this.redis.incr(`${this.prefix}:generation:${deploymentId}:${replicaId}`));
  }
  async publishLease(lease: ObservationLease, ttlSeconds: 30) {
    const key = `${this.prefix}:${lease.deploymentId}:${lease.membershipGeneration}:${lease.replicaId}:${lease.replicaGeneration}`;
    const result = await this.redis.eval(
      `local old=redis.call('GET',KEYS[1]); if old then local g=cjson.decode(old).leaseGeneration; if string.len(g)>string.len(ARGV[2]) or (string.len(g)==string.len(ARGV[2]) and g>ARGV[2]) then return 0 end end; redis.call('SET',KEYS[1],ARGV[1],'EX',ARGV[3]); return 1`,
      1,
      key,
      canonicalizeRfc8785(lease),
      lease.leaseGeneration,
      String(ttlSeconds),
    );
    if (result !== 1) throw new Error("stale observation lease generation");
  }
  async listLeases(deploymentId: string, membershipGeneration: string) {
    const prefix = `${this.prefix}:${deploymentId}:${membershipGeneration}:`,
      keys: string[] = [];
    let cursor = "0";
    do {
      const [next, page] = await this.redis.scan(cursor, "MATCH", `${prefix}*`, "COUNT", 100);
      cursor = next;
      keys.push(...page);
    } while (cursor !== "0");
    const leases: ObservationLease[] = [];
    for (const key of keys) {
      const value = await this.redis.get(key);
      if (value === null) continue;
      const parsed: unknown = JSON.parse(value);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
        throw new Error("invalid observation lease");
      const lease = parsed as Record<string, unknown>,
        expected = [
          "authorityEpoch",
          "currentKid",
          "deploymentId",
          "digest",
          "expiresAt",
          "issuerDigest",
          "leaseGeneration",
          "membershipGeneration",
          "observedRedisTime",
          "publicKids",
          "replicaGeneration",
          "replicaId",
          "revision",
        ];
      if (Object.keys(lease).sort().join("\0") !== expected.sort().join("\0"))
        throw new Error("invalid observation lease members");
      for (const field of [
        "authorityEpoch",
        "expiresAt",
        "leaseGeneration",
        "membershipGeneration",
        "observedRedisTime",
        "replicaGeneration",
        "revision",
      ])
        if (typeof lease[field] !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(lease[field]))
          throw new Error("invalid observation lease counter");
      if (
        lease.deploymentId !== deploymentId ||
        lease.membershipGeneration !== membershipGeneration
      )
        throw new Error("observation lease scope mismatch");
      const suffix = key.slice(prefix.length).split(":");
      if (
        suffix.length !== 2 ||
        suffix[0] !== lease.replicaId ||
        suffix[1] !== lease.replicaGeneration
      )
        throw new Error("observation lease key mismatch");
      if (
        typeof lease.digest !== "string" ||
        !/^[0-9a-f]{64}$/.test(lease.digest) ||
        typeof lease.issuerDigest !== "string" ||
        !/^[0-9a-f]{64}$/.test(lease.issuerDigest) ||
        typeof lease.currentKid !== "string" ||
        typeof lease.replicaId !== "string" ||
        !Array.isArray(lease.publicKids) ||
        lease.publicKids.some((kid) => typeof kid !== "string")
      )
        throw new Error("invalid observation lease fields");
      leases.push(lease as unknown as ObservationLease);
    }
    return leases;
  }
}
