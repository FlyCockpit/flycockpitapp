/**
 * Postgres control plane for the signed public service policy: immutable policy
 * rows, the eight closed consumer groups, replica leases, per-activation
 * membership snapshots, the append-only outbox, and the durable state machine
 * (import → scheduled → activation/convergence). All correctness predicates are
 * evaluated against DATABASE time (`NOW()`, `to_timestamp`, `INTERVAL`) inside
 * Serializable transactions — never a process clock. The one injected clock is
 * `importPolicyJws`'s `now` skew check, which lives in `remote-public-policy.ts`.
 *
 * The `SqlClient` transaction seam is REUSED verbatim from
 * `remote-authority-storage.ts` — this module does not invent a second one.
 * The outbox is append-only: there is no update/delete path for it anywhere in
 * this file.
 */
import {
  type ChangeClass,
  CONVERGENCE_TIMEOUT_SECONDS,
  CRITICAL_CONSUMER_IDS,
  type PolicyRowState,
  REPLICA_LEASE_TTL_SECONDS,
  STALE_REAP_GRACE_SECONDS,
} from "@flycockpit/cockpit-protocol";
import type { SqlClient } from "./remote-authority-storage";

export type { SqlClient } from "./remote-authority-storage";

const text = (value: unknown): string => String(value);

// ---------------------------------------------------------------------------
// Row + argument shapes crossing the store boundary
// ---------------------------------------------------------------------------

/** An immutable policy row projected for the business layer (decimal-string u64s). */
export interface StoredPolicyRow {
  policyId: string;
  serviceVersion: string;
  changeClass: string;
  compactJws: string;
  payloadDigest: string;
  previousDigest: string | null;
  notBefore: string;
  state: PolicyRowState;
}

/** A candidate row for the activation scan, with DB-time predicates precomputed. */
export interface ActivatableRow extends StoredPolicyRow {
  dueNow: boolean;
  convergenceTimedOut: boolean;
}

export interface InsertScheduledPolicyArgs {
  policyId: string;
  serviceVersion: string;
  changeClass: ChangeClass;
  compactJws: string;
  payloadDigest: string;
  previousDigest: string | null;
  issuedAt: string;
  notBefore: string;
  verifiedKid: string;
  verifiedJwk: string;
  thumbprint: string;
  ringDigest: string;
}

export interface RegisterLeaseArgs {
  consumerId: string;
  replicaId: string;
  evaluatorDigest: string;
  serviceVersion: string;
  policyDigest: string;
}

export interface LeaseHeartbeatArgs {
  replicaId: string;
  replicaGeneration: string;
  evaluatorDigest: string;
  serviceVersion: string;
  policyDigest: string;
}

export interface GroupAckResult {
  acked: boolean;
  recaptured: boolean;
  membershipGeneration: string;
}

/**
 * The set of SQL operations the pure import logic and the activation reducer
 * need. `PostgresPolicyStore` is the production implementation; tests drive a
 * fake `SqlClient` (or a fake `PolicyStore`) with injected DB time.
 */
export interface PolicyStore {
  loadPolicyTip(): Promise<StoredPolicyRow | null>;
  loadPolicyByServiceVersion(serviceVersion: string): Promise<StoredPolicyRow | null>;
  insertScheduledPolicy(args: InsertScheduledPolicyArgs): Promise<StoredPolicyRow>;
  seedConsumerGroups(): Promise<void>;
  loadRequiredConsumerIds(): Promise<string[]>;
  registerReplicaLease(
    args: RegisterLeaseArgs,
  ): Promise<{ replicaId: string; replicaGeneration: string; membershipGeneration: string }>;
  renewReplicaLease(args: LeaseHeartbeatArgs): Promise<boolean>;
  drainReplicaLease(args: { replicaId: string; replicaGeneration: string }): Promise<boolean>;
  removeReplicaLease(args: {
    replicaId: string;
    replicaGeneration: string;
  }): Promise<{ removed: boolean; membershipGeneration: string | null }>;
  markExpiredLeasesStale(): Promise<string[]>;
  reapStaleLease(args: {
    replicaId: string;
    evidence: string;
  }): Promise<{ reaped: boolean; membershipGeneration: string | null }>;
  recordGroupAck(args: { policyId: string; consumerId: string }): Promise<GroupAckResult>;
  loadActivatableRows(): Promise<ActivatableRow[]>;
  activateNarrowingRow(policyId: string): Promise<boolean>;
  prepareWideningRow(policyId: string): Promise<boolean>;
  markPolicyActive(policyId: string): Promise<boolean>;
  markConvergenceFailed(policyId: string): Promise<boolean>;
  advanceWideningPointer(policyId: string): Promise<boolean>;
  markScheduledFailed(policyId: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Column projections
// ---------------------------------------------------------------------------

const POLICY_COLUMNS =
  '"policyId","serviceVersion"::text AS "serviceVersion","changeClass","compactJws","payloadDigest","previousDigest",EXTRACT(EPOCH FROM "notBefore")::bigint::text AS "notBefore","state"';

function mapPolicyRow(row: Record<string, unknown>): StoredPolicyRow {
  return {
    policyId: text(row.policyId),
    serviceVersion: text(row.serviceVersion),
    changeClass: text(row.changeClass),
    compactJws: text(row.compactJws),
    payloadDigest: text(row.payloadDigest),
    previousDigest: row.previousDigest === null ? null : text(row.previousDigest),
    notBefore: text(row.notBefore),
    state: text(row.state) as PolicyRowState,
  };
}

export class PostgresPolicyStore implements PolicyStore {
  constructor(private readonly db: SqlClient) {}

  async loadPolicyTip(): Promise<StoredPolicyRow | null> {
    const rows = await this.db.$queryRawUnsafe<Array<Record<string, unknown>>>(
      `SELECT ${POLICY_COLUMNS} FROM remote_public_service_policies ORDER BY "serviceVersion" DESC LIMIT 1`,
    );
    const row = rows[0];
    return row ? mapPolicyRow(row) : null;
  }

  async loadPolicyByServiceVersion(serviceVersion: string): Promise<StoredPolicyRow | null> {
    const rows = await this.db.$queryRawUnsafe<Array<Record<string, unknown>>>(
      `SELECT ${POLICY_COLUMNS} FROM remote_public_service_policies WHERE "serviceVersion"=$1::numeric`,
      serviceVersion,
    );
    const row = rows[0];
    return row ? mapPolicyRow(row) : null;
  }

  async insertScheduledPolicy(args: InsertScheduledPolicyArgs): Promise<StoredPolicyRow> {
    return this.db.$transaction(
      async (tx) => {
        const inserted = await tx.$executeRawUnsafe(
          `INSERT INTO remote_public_service_policies ("policyId","serviceVersion","changeClass","compactJws","payloadDigest","previousDigest","issuedAt","notBefore","state","verifiedKid","verifiedJwk","thumbprint","ringDigest","supersedesPolicyId","createdAt","updatedAt") VALUES ($1,$2::numeric,$3,$4,$5,$6,to_timestamp($7::numeric),to_timestamp($8::numeric),'scheduled',$9,$10,$11,$12,NULL,NOW(),NOW()) ON CONFLICT ("serviceVersion") DO NOTHING`,
          args.policyId,
          args.serviceVersion,
          args.changeClass,
          args.compactJws,
          args.payloadDigest,
          args.previousDigest,
          args.issuedAt,
          args.notBefore,
          args.verifiedKid,
          args.verifiedJwk,
          args.thumbprint,
          args.ringDigest,
        );
        if (inserted === 1) {
          await tx.$executeRawUnsafe(
            `INSERT INTO remote_public_service_policy_outbox ("eventId","policyId","serviceVersion","eventType","payload","createdAt") VALUES ($1,$2,$3::numeric,'remote_public_service_policy_scheduled',$4,NOW()) ON CONFLICT ("policyId","eventType") DO NOTHING`,
            crypto.randomUUID(),
            args.policyId,
            args.serviceVersion,
            args.compactJws,
          );
        }
        const rows = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT ${POLICY_COLUMNS} FROM remote_public_service_policies WHERE "serviceVersion"=$1::numeric`,
          args.serviceVersion,
        );
        const row = rows[0];
        if (!row) throw new Error("scheduled policy row vanished after insert");
        return mapPolicyRow(row);
      },
      { isolationLevel: "Serializable" },
    );
  }

  async seedConsumerGroups(): Promise<void> {
    for (const consumerId of CRITICAL_CONSUMER_IDS) {
      await this.db.$executeRawUnsafe(
        `INSERT INTO remote_policy_consumer_groups ("consumerId","state","membershipGeneration","evaluatorDigest","createdAt","updatedAt") VALUES ($1,'disabled',0,$2,NOW(),NOW()) ON CONFLICT ("consumerId") DO NOTHING`,
        consumerId,
        "0".repeat(64),
      );
    }
  }

  async loadRequiredConsumerIds(): Promise<string[]> {
    const rows = await this.db.$queryRawUnsafe<Array<Record<string, unknown>>>(
      `SELECT "consumerId" FROM remote_policy_consumer_groups WHERE "state"='required' ORDER BY "consumerId"`,
    );
    return rows.map((row) => text(row.consumerId));
  }

  async registerReplicaLease(args: RegisterLeaseArgs) {
    return this.db.$transaction(
      async (tx) => {
        const groups = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "membershipGeneration"::text AS "membershipGeneration" FROM remote_policy_consumer_groups WHERE "consumerId"=$1 FOR UPDATE`,
          args.consumerId,
        );
        const group = groups[0];
        if (!group) throw new Error(`unknown consumer group ${args.consumerId}`);
        const nextMembership = (BigInt(text(group.membershipGeneration)) + 1n).toString();
        await tx.$executeRawUnsafe(
          `UPDATE remote_policy_consumer_groups SET "membershipGeneration"=$2::numeric,"updatedAt"=NOW() WHERE "consumerId"=$1`,
          args.consumerId,
          nextMembership,
        );
        const existing = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "replicaGeneration"::text AS "replicaGeneration" FROM remote_policy_consumer_replica_leases WHERE "replicaId"=$1 FOR UPDATE`,
          args.replicaId,
        );
        let replicaGeneration: string;
        if (existing[0]) {
          replicaGeneration = (BigInt(text(existing[0].replicaGeneration)) + 1n).toString();
          await tx.$executeRawUnsafe(
            `UPDATE remote_policy_consumer_replica_leases SET "consumerId"=$2,"replicaGeneration"=$3::numeric,"membershipGeneration"=$4::numeric,"evaluatorDigest"=$5,"serviceVersion"=$6::numeric,"policyDigest"=$7,"state"='starting',"observedAt"=NOW(),"expiresAt"=NOW()+INTERVAL '${REPLICA_LEASE_TTL_SECONDS} seconds',"updatedAt"=NOW() WHERE "replicaId"=$1`,
            args.replicaId,
            args.consumerId,
            replicaGeneration,
            nextMembership,
            args.evaluatorDigest,
            args.serviceVersion,
            args.policyDigest,
          );
        } else {
          replicaGeneration = "1";
          await tx.$executeRawUnsafe(
            `INSERT INTO remote_policy_consumer_replica_leases ("replicaId","consumerId","replicaGeneration","membershipGeneration","evaluatorDigest","serviceVersion","policyDigest","state","observedAt","expiresAt","createdAt","updatedAt") VALUES ($1,$2,1,$3::numeric,$4,$5::numeric,$6,'starting',NOW(),NOW()+INTERVAL '${REPLICA_LEASE_TTL_SECONDS} seconds',NOW(),NOW())`,
            args.replicaId,
            args.consumerId,
            nextMembership,
            args.evaluatorDigest,
            args.serviceVersion,
            args.policyDigest,
          );
        }
        return {
          replicaId: args.replicaId,
          replicaGeneration,
          membershipGeneration: nextMembership,
        };
      },
      { isolationLevel: "Serializable" },
    );
  }

  async renewReplicaLease(args: LeaseHeartbeatArgs): Promise<boolean> {
    const changed = await this.db.$executeRawUnsafe(
      `UPDATE remote_policy_consumer_replica_leases SET "state"='ready',"evaluatorDigest"=$3,"serviceVersion"=$4::numeric,"policyDigest"=$5,"observedAt"=NOW(),"expiresAt"=NOW()+INTERVAL '${REPLICA_LEASE_TTL_SECONDS} seconds',"updatedAt"=NOW() WHERE "replicaId"=$1 AND "replicaGeneration"=$2::numeric AND ("state"='starting' OR "state"='ready')`,
      args.replicaId,
      args.replicaGeneration,
      args.evaluatorDigest,
      args.serviceVersion,
      args.policyDigest,
    );
    return changed === 1;
  }

  async drainReplicaLease(args: {
    replicaId: string;
    replicaGeneration: string;
  }): Promise<boolean> {
    const changed = await this.db.$executeRawUnsafe(
      `UPDATE remote_policy_consumer_replica_leases SET "state"='draining',"updatedAt"=NOW() WHERE "replicaId"=$1 AND "replicaGeneration"=$2::numeric AND ("state"='starting' OR "state"='ready')`,
      args.replicaId,
      args.replicaGeneration,
    );
    return changed === 1;
  }

  async removeReplicaLease(args: { replicaId: string; replicaGeneration: string }) {
    return this.db.$transaction(
      async (tx) => {
        const rows = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "consumerId","state",("expiresAt"<=NOW()) AS "expired" FROM remote_policy_consumer_replica_leases WHERE "replicaId"=$1 AND "replicaGeneration"=$2::numeric FOR UPDATE`,
          args.replicaId,
          args.replicaGeneration,
        );
        const lease = rows[0];
        if (lease?.state !== "draining" || lease.expired !== true) {
          return { removed: false, membershipGeneration: null };
        }
        const membershipGeneration = await this.bumpMembership(tx, text(lease.consumerId));
        await tx.$executeRawUnsafe(
          `DELETE FROM remote_policy_consumer_replica_leases WHERE "replicaId"=$1`,
          args.replicaId,
        );
        return { removed: true, membershipGeneration };
      },
      { isolationLevel: "Serializable" },
    );
  }

  async markExpiredLeasesStale(): Promise<string[]> {
    const rows = await this.db.$queryRawUnsafe<Array<Record<string, unknown>>>(
      `UPDATE remote_policy_consumer_replica_leases SET "state"='stale',"updatedAt"=NOW() WHERE ("state"='starting' OR "state"='ready') AND "expiresAt"<=NOW() RETURNING "replicaId"`,
    );
    return rows.map((row) => text(row.replicaId));
  }

  async reapStaleLease(args: { replicaId: string; evidence: string }) {
    if (args.evidence.trim().length === 0) {
      throw new Error("reaping a stale lease requires a recorded operator evidence string");
    }
    return this.db.$transaction(
      async (tx) => {
        const rows = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "consumerId","state",(NOW()>="expiresAt"+INTERVAL '${STALE_REAP_GRACE_SECONDS} seconds') AS "reapable" FROM remote_policy_consumer_replica_leases WHERE "replicaId"=$1 FOR UPDATE`,
          args.replicaId,
        );
        const lease = rows[0];
        if (lease?.state !== "stale" || lease.reapable !== true) {
          return { reaped: false, membershipGeneration: null };
        }
        const consumerId = text(lease.consumerId);
        const membershipGeneration = await this.bumpMembership(tx, consumerId);
        // Durably record the operator evidence BEFORE deleting the lease, in the
        // same transaction, so an authenticated reap always leaves an audit row.
        await tx.$executeRawUnsafe(
          `INSERT INTO remote_policy_lease_reap_audits ("auditId","replicaId","consumerId","membershipGeneration","evidence","reapedAt") VALUES ($1,$2,$3,$4::numeric,$5,NOW())`,
          crypto.randomUUID(),
          args.replicaId,
          consumerId,
          membershipGeneration,
          args.evidence,
        );
        await tx.$executeRawUnsafe(
          `DELETE FROM remote_policy_consumer_replica_leases WHERE "replicaId"=$1`,
          args.replicaId,
        );
        return { reaped: true, membershipGeneration };
      },
      { isolationLevel: "Serializable" },
    );
  }

  private async bumpMembership(tx: SqlClient, consumerId: string): Promise<string> {
    const groups = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
      `SELECT "membershipGeneration"::text AS "membershipGeneration" FROM remote_policy_consumer_groups WHERE "consumerId"=$1 FOR UPDATE`,
      consumerId,
    );
    const group = groups[0];
    if (!group) throw new Error(`unknown consumer group ${consumerId}`);
    const next = (BigInt(text(group.membershipGeneration)) + 1n).toString();
    await tx.$executeRawUnsafe(
      `UPDATE remote_policy_consumer_groups SET "membershipGeneration"=$2::numeric,"updatedAt"=NOW() WHERE "consumerId"=$1`,
      consumerId,
      next,
    );
    return next;
  }

  async recordGroupAck(args: { policyId: string; consumerId: string }): Promise<GroupAckResult> {
    return this.db.$transaction(
      async (tx) => {
        const policies = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "serviceVersion"::text AS "serviceVersion","payloadDigest" FROM remote_public_service_policies WHERE "policyId"=$1`,
          args.policyId,
        );
        const policy = policies[0];
        if (!policy) throw new Error(`unknown policy ${args.policyId}`);
        const groups = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "state","membershipGeneration"::text AS "membershipGeneration","evaluatorDigest" FROM remote_policy_consumer_groups WHERE "consumerId"=$1 FOR UPDATE`,
          args.consumerId,
        );
        const group = groups[0];
        // Unknown consumer or a group that is not required cannot durably ACK:
        // drop any stale snapshot and report un-acked.
        if (group?.state !== "required") {
          await this.deleteSnapshot(tx, args.policyId, args.consumerId);
          return {
            acked: false,
            recaptured: true,
            membershipGeneration: group ? text(group.membershipGeneration) : "0",
          };
        }
        const currentGeneration = text(group.membershipGeneration);
        const snapshot = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "membershipGeneration"::text AS "membershipGeneration","replicaId","replicaGeneration"::text AS "replicaGeneration" FROM remote_policy_activation_snapshots WHERE "policyId"=$1 AND "consumerId"=$2`,
          args.policyId,
          args.consumerId,
        );

        // Membership changed underneath the snapshot (join/replacement/drain/
        // removal/reap): the in-flight ACK is invalid; recapture from the leases
        // live right now and report un-acked.
        const capturedGeneration = snapshot[0] ? text(snapshot[0].membershipGeneration) : null;
        if (snapshot.length === 0 || capturedGeneration !== currentGeneration) {
          await this.recaptureSnapshot(tx, args.policyId, args.consumerId, currentGeneration);
          return { acked: false, recaptured: true, membershipGeneration: currentGeneration };
        }

        const leases = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "replicaId","replicaGeneration"::text AS "replicaGeneration","state","evaluatorDigest","serviceVersion"::text AS "serviceVersion","policyDigest" FROM remote_policy_consumer_replica_leases WHERE "consumerId"=$1`,
          args.consumerId,
        );
        const byReplica = new Map(leases.map((row) => [text(row.replicaId), row]));

        let invalidated = false;
        let allReady = true;
        for (const snap of snapshot) {
          const lease = byReplica.get(text(snap.replicaId));
          if (
            !lease ||
            lease.state === "stale" ||
            text(lease.replicaGeneration) !== text(snap.replicaGeneration) ||
            text(lease.evaluatorDigest) !== text(group.evaluatorDigest)
          ) {
            // Reaped, replaced, stale, or evaluator divergence: invalidating.
            invalidated = true;
            allReady = false;
            continue;
          }
          if (
            lease.state !== "ready" ||
            text(lease.serviceVersion) !== text(policy.serviceVersion) ||
            text(lease.policyDigest) !== text(policy.payloadDigest)
          ) {
            // Still converging (starting / not-yet-on-this-policy): not an ACK,
            // but not an invalidation either.
            allReady = false;
          }
        }

        if (invalidated) {
          await this.recaptureSnapshot(tx, args.policyId, args.consumerId, currentGeneration);
          return { acked: false, recaptured: true, membershipGeneration: currentGeneration };
        }
        return { acked: allReady, recaptured: false, membershipGeneration: currentGeneration };
      },
      { isolationLevel: "Serializable" },
    );
  }

  private async deleteSnapshot(tx: SqlClient, policyId: string, consumerId: string): Promise<void> {
    await tx.$executeRawUnsafe(
      `DELETE FROM remote_policy_activation_snapshots WHERE "policyId"=$1 AND "consumerId"=$2`,
      policyId,
      consumerId,
    );
  }

  private async recaptureSnapshot(
    tx: SqlClient,
    policyId: string,
    consumerId: string,
    membershipGeneration: string,
  ): Promise<void> {
    await this.deleteSnapshot(tx, policyId, consumerId);
    const leases = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
      `SELECT "replicaId","replicaGeneration"::text AS "replicaGeneration" FROM remote_policy_consumer_replica_leases WHERE "consumerId"=$1 AND "state"<>'stale'`,
      consumerId,
    );
    for (const lease of leases) {
      await tx.$executeRawUnsafe(
        `INSERT INTO remote_policy_activation_snapshots ("id","policyId","consumerId","membershipGeneration","replicaId","replicaGeneration","createdAt") VALUES ($1,$2,$3,$4::numeric,$5,$6::numeric,NOW())`,
        crypto.randomUUID(),
        policyId,
        consumerId,
        membershipGeneration,
        text(lease.replicaId),
        text(lease.replicaGeneration),
      );
    }
  }

  async loadActivatableRows(): Promise<ActivatableRow[]> {
    const rows = await this.db.$queryRawUnsafe<Array<Record<string, unknown>>>(
      `SELECT ${POLICY_COLUMNS},("notBefore"<=NOW()) AS "dueNow",("updatedAt"+INTERVAL '${CONVERGENCE_TIMEOUT_SECONDS} seconds'<=NOW()) AS "convergenceTimedOut" FROM remote_public_service_policies WHERE "state" IN ('scheduled','preparing','active_converging') ORDER BY "serviceVersion"`,
    );
    return rows.map((row) => ({
      ...mapPolicyRow(row),
      dueNow: row.dueNow === true,
      convergenceTimedOut: row.convergenceTimedOut === true,
    }));
  }

  async activateNarrowingRow(policyId: string): Promise<boolean> {
    return this.enterConvergence(policyId, "narrowing_or_equal", "active_converging", true);
  }

  async prepareWideningRow(policyId: string): Promise<boolean> {
    return this.enterConvergence(policyId, "widening", "preparing", false);
  }

  private async enterConvergence(
    policyId: string,
    changeClass: ChangeClass,
    nextState: PolicyRowState,
    appendActivatedOutbox: boolean,
  ): Promise<boolean> {
    return this.db.$transaction(
      async (tx) => {
        const rows = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "serviceVersion"::text AS "serviceVersion","compactJws","changeClass" FROM remote_public_service_policies WHERE "policyId"=$1 AND "state"='scheduled' AND "changeClass"=$2 AND "notBefore"<=NOW() FOR UPDATE`,
          policyId,
          changeClass,
        );
        const row = rows[0];
        if (!row) return false;
        const priorPolicyId =
          nextState === "active_converging"
            ? await this.supersedePriorPointer(tx, text(row.serviceVersion))
            : null;
        await tx.$executeRawUnsafe(
          `UPDATE remote_public_service_policies SET "state"=$2::"RemotePolicyRowState","supersedesPolicyId"=$3,"updatedAt"=NOW() WHERE "policyId"=$1`,
          policyId,
          nextState,
          priorPolicyId,
        );
        await this.captureSnapshots(tx, policyId);
        if (appendActivatedOutbox) {
          await this.appendActivatedOutbox(
            tx,
            policyId,
            text(row.serviceVersion),
            text(row.compactJws),
          );
        }
        return true;
      },
      { isolationLevel: "Serializable" },
    );
  }

  private async supersedePriorPointer(
    tx: SqlClient,
    serviceVersion: string,
  ): Promise<string | null> {
    const rows = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
      `SELECT "policyId" FROM remote_public_service_policies WHERE "state" IN ('active','active_converging','active_convergence_failed') AND "serviceVersion"<$1::numeric ORDER BY "serviceVersion" DESC LIMIT 1 FOR UPDATE`,
      serviceVersion,
    );
    return rows[0] ? text(rows[0].policyId) : null;
  }

  private async captureSnapshots(tx: SqlClient, policyId: string): Promise<void> {
    const leases = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
      `SELECT l."consumerId",l."replicaId",l."replicaGeneration"::text AS "replicaGeneration",g."membershipGeneration"::text AS "membershipGeneration" FROM remote_policy_consumer_replica_leases l JOIN remote_policy_consumer_groups g ON g."consumerId"=l."consumerId" WHERE g."state"='required' AND l."state"<>'stale' FOR UPDATE OF l`,
    );
    for (const lease of leases) {
      await tx.$executeRawUnsafe(
        `INSERT INTO remote_policy_activation_snapshots ("id","policyId","consumerId","membershipGeneration","replicaId","replicaGeneration","createdAt") VALUES ($1,$2,$3,$4::numeric,$5,$6::numeric,NOW())`,
        crypto.randomUUID(),
        policyId,
        text(lease.consumerId),
        text(lease.membershipGeneration),
        text(lease.replicaId),
        text(lease.replicaGeneration),
      );
    }
  }

  private async appendActivatedOutbox(
    tx: SqlClient,
    policyId: string,
    serviceVersion: string,
    payload: string,
  ): Promise<void> {
    await tx.$executeRawUnsafe(
      `INSERT INTO remote_public_service_policy_outbox ("eventId","policyId","serviceVersion","eventType","payload","createdAt") VALUES ($1,$2,$3::numeric,'remote_public_service_policy_activated',$4,NOW()) ON CONFLICT ("policyId","eventType") DO NOTHING`,
      crypto.randomUUID(),
      policyId,
      serviceVersion,
      payload,
    );
  }

  async markPolicyActive(policyId: string): Promise<boolean> {
    const changed = await this.db.$executeRawUnsafe(
      `UPDATE remote_public_service_policies SET "state"='active',"updatedAt"=NOW() WHERE "policyId"=$1 AND "state"='active_converging'`,
      policyId,
    );
    return changed === 1;
  }

  async markConvergenceFailed(policyId: string): Promise<boolean> {
    // Authoritative and never rolled back: the narrowing pointer stays advanced.
    const changed = await this.db.$executeRawUnsafe(
      `UPDATE remote_public_service_policies SET "state"='active_convergence_failed',"updatedAt"=NOW() WHERE "policyId"=$1 AND "state"='active_converging'`,
      policyId,
    );
    return changed === 1;
  }

  async advanceWideningPointer(policyId: string): Promise<boolean> {
    return this.db.$transaction(
      async (tx) => {
        const rows = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `SELECT "serviceVersion"::text AS "serviceVersion","compactJws" FROM remote_public_service_policies WHERE "policyId"=$1 AND "state"='preparing' FOR UPDATE`,
          policyId,
        );
        const row = rows[0];
        if (!row) return false;
        const priorPolicyId = await this.supersedePriorPointer(tx, text(row.serviceVersion));
        await tx.$executeRawUnsafe(
          `UPDATE remote_public_service_policies SET "state"='active',"supersedesPolicyId"=$2,"updatedAt"=NOW() WHERE "policyId"=$1`,
          policyId,
          priorPolicyId,
        );
        await this.appendActivatedOutbox(
          tx,
          policyId,
          text(row.serviceVersion),
          text(row.compactJws),
        );
        return true;
      },
      { isolationLevel: "Serializable" },
    );
  }

  async markScheduledFailed(policyId: string): Promise<boolean> {
    // The old policy stays authoritative: the pointer was never advanced.
    const changed = await this.db.$executeRawUnsafe(
      `UPDATE remote_public_service_policies SET "state"='scheduled_failed',"updatedAt"=NOW() WHERE "policyId"=$1 AND "state"='preparing'`,
      policyId,
    );
    return changed === 1;
  }
}

// ---------------------------------------------------------------------------
// Activation orchestrator (BullMQ wakeup → DB-time state machine)
// ---------------------------------------------------------------------------

export type ActivationAction =
  | "activated_narrowing"
  | "preparing_widening"
  | "active"
  | "convergence_failed"
  | "scheduled_failed"
  | "converging"
  | "preparing"
  | "skipped";

export interface ActivationOutcome {
  policyId: string;
  action: ActivationAction;
}

/**
 * Advance every durable policy row that is due or mid-convergence. Idempotent
 * and DB-time authoritative: a missed or late wakeup changes only latency,
 * never correctness. Resumes from durable row state on crash/restart (the scan
 * itself is the recovery pass over scheduled/preparing/active_converging rows).
 */
export async function activateDuePolicies({
  store,
}: {
  store: PolicyStore;
}): Promise<ActivationOutcome[]> {
  await store.markExpiredLeasesStale();
  const rows = await store.loadActivatableRows();
  const requiredConsumerIds = await store.loadRequiredConsumerIds();
  const outcomes: ActivationOutcome[] = [];

  for (const row of rows) {
    if (row.state === "scheduled" && row.dueNow) {
      if (row.changeClass === "narrowing_or_equal") {
        const ok = await store.activateNarrowingRow(row.policyId);
        outcomes.push({ policyId: row.policyId, action: ok ? "activated_narrowing" : "skipped" });
      } else {
        const ok = await store.prepareWideningRow(row.policyId);
        outcomes.push({ policyId: row.policyId, action: ok ? "preparing_widening" : "skipped" });
      }
      continue;
    }
    if (row.state === "active_converging") {
      if (await isPolicyConverged(store, row.policyId, requiredConsumerIds)) {
        await store.markPolicyActive(row.policyId);
        outcomes.push({ policyId: row.policyId, action: "active" });
      } else if (row.convergenceTimedOut) {
        await store.markConvergenceFailed(row.policyId);
        outcomes.push({ policyId: row.policyId, action: "convergence_failed" });
      } else {
        outcomes.push({ policyId: row.policyId, action: "converging" });
      }
      continue;
    }
    if (row.state === "preparing") {
      if (await isPolicyConverged(store, row.policyId, requiredConsumerIds)) {
        await store.advanceWideningPointer(row.policyId);
        outcomes.push({ policyId: row.policyId, action: "active" });
      } else if (row.convergenceTimedOut) {
        await store.markScheduledFailed(row.policyId);
        outcomes.push({ policyId: row.policyId, action: "scheduled_failed" });
      } else {
        outcomes.push({ policyId: row.policyId, action: "preparing" });
      }
    }
  }
  return outcomes;
}

/**
 * A policy is converged when EVERY required consumer group durably ACKs its
 * captured snapshot (unchanged membership generation, every snapshotted replica
 * `ready` with the exact evaluator + policy digest). An empty required-group set
 * is trivially converged; a required group with no ready snapshot is not.
 */
async function isPolicyConverged(
  store: PolicyStore,
  policyId: string,
  requiredConsumerIds: readonly string[],
): Promise<boolean> {
  for (const consumerId of requiredConsumerIds) {
    const { acked } = await store.recordGroupAck({ policyId, consumerId });
    if (!acked) return false;
  }
  return true;
}
