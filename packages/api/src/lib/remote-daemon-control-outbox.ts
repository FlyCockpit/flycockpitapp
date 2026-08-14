/**
 * Per-instance daemon control-outbox page reader.
 *
 * This is the durable **server→daemon** control stream authority: the Postgres
 * table `RemoteDaemonControlOutbox`, whose sequence scope is exactly
 * `(daemonInstanceProtocolId, daemonCertificateGeneration)` and whose durable
 * payload is the exact compact ES256 control-event JWS
 * (`typ:"flycockpit-remote-control-event+jws"`). Delivery re-emits
 * `controlEventJws` byte-for-byte; this module never re-signs, re-encodes, or
 * wraps the bytes.
 *
 * It is deliberately **disjoint** from `RemoteSignalingAttemptStore` (Redis
 * attempt/discovery streams) and from the deployment-scoped
 * `RemoteAuthorityControlOutbox` (`remote_authority_control_outbox`) — a control
 * page reader must never surface deployment-scoped authority rows as the daemon
 * stream. Attempt-Redis loss and control-Postgres loss therefore fail
 * independently.
 *
 * Wake-on-append is a Redis Pub/Sub signal only ({@link
 * notifyDaemonControlOutboxAppend}): the payload carries the instance scope plus
 * a high-water hint, and every byte a socket delivers is read back through
 * {@link RemoteDaemonControlOutboxStore.readDaemonControlOutboxPage} from
 * Postgres. Control-event JWS bytes are never dual-written into Redis.
 */
import { decodeProtocolIdBase64Url } from "@flycockpit/cockpit-protocol";
import type { SqlClient } from "./remote-authority-storage";

/** Page caps: at most 64 events AND at most 512 KiB aggregate JWS UTF-8 bytes. */
export const REMOTE_DAEMON_CONTROL_OUTBOX_MAX_EVENTS = 64;
export const REMOTE_DAEMON_CONTROL_OUTBOX_MAX_BYTES = 512 * 1024;

/** Redis Pub/Sub control-outbox wake channel prefix (dedicated; not attempt-wake). */
export const REMOTE_DAEMON_CONTROL_OUTBOX_WAKE_PREFIX = "flycockpit:remote-control:outbox-wake:";

export class RemoteDaemonControlOutboxError extends Error {
  constructor(
    readonly code: "corrupt" | "unavailable",
    message: string = code,
  ) {
    super(message);
  }
}

export interface RemoteDaemonControlOutboxEventV1 {
  controlSeq: bigint;
  /** The 16-byte event id (decoded from the stored base64url protocol id). */
  eventId: Uint8Array;
  /** The exact compact ES256 control-event JWS stored in the row. */
  controlEventJws: string;
  /** Optional mirror of the FCRC payload digest; authenticity is the JWS. */
  payloadDigest?: string;
}

export interface RemoteDaemonControlOutboxPageV1 {
  events: RemoteDaemonControlOutboxEventV1[];
  /**
   * The true scope-wide max `controlSeq` (`0n` when the scope has no rows),
   * independent of `afterControlSeq` — so a daemon claiming a cursor above the
   * real high-water is always detectable as a conflict, even on an empty outbox.
   */
  highWaterSeq: bigint;
  /** True when committed rows remain after this page. */
  truncated: boolean;
}

export interface ReadDaemonControlOutboxPageInput {
  /** 22-char base64url protocol id — the same identifier used as the Postgres key. */
  daemonInstanceProtocolId: string;
  daemonCertificateGeneration: bigint;
  /** Exclusive lower bound; `0n` reads from the start. */
  afterControlSeq: bigint;
}

export interface RemoteDaemonControlOutboxStore {
  /**
   * Return the next page of control events with `controlSeq > afterControlSeq`
   * in `controlSeq` ASC order, capped at ≤64 events AND ≤512 KiB aggregate
   * `controlEventJws` UTF-8 bytes (event count shrinks to fit the byte cap). A
   * single JWS whose UTF-8 length alone exceeds 512 KiB is a hard `corrupt`
   * error (fail closed — never skip the row, which would brick the sequence).
   */
  readDaemonControlOutboxPage(
    input: ReadDaemonControlOutboxPageInput,
  ): Promise<RemoteDaemonControlOutboxPageV1>;
}

const jwsByteLength = (jws: string): number => Buffer.byteLength(jws, "utf8");

/**
 * Apply the shared page caps to an already-ordered (`controlSeq` ASC), already
 * `afterControlSeq`-filtered list of rows. `highWater` is the true max controlSeq
 * across the whole scope (independent of the caps), so `truncated` is correct
 * even when the byte cap shrinks the page below the row count fetched.
 */
function buildPage(
  ordered: readonly RemoteDaemonControlOutboxEventV1[],
  highWater: bigint,
): RemoteDaemonControlOutboxPageV1 {
  const events: RemoteDaemonControlOutboxEventV1[] = [];
  let bytes = 0;
  for (const event of ordered) {
    const length = jwsByteLength(event.controlEventJws);
    if (length > REMOTE_DAEMON_CONTROL_OUTBOX_MAX_BYTES)
      throw new RemoteDaemonControlOutboxError("corrupt", "control event JWS exceeds 512 KiB");
    if (events.length >= REMOTE_DAEMON_CONTROL_OUTBOX_MAX_EVENTS) break;
    if (bytes + length > REMOTE_DAEMON_CONTROL_OUTBOX_MAX_BYTES) break;
    events.push(event);
    bytes += length;
  }
  const last = events.at(-1);
  const truncated = last !== undefined && last.controlSeq < highWater;
  return { events, highWaterSeq: highWater, truncated };
}

/** Decode the stored base64url eventId into its canonical 16 bytes (fail closed). */
function decodeEventId(stored: unknown): Uint8Array {
  if (typeof stored !== "string") throw new RemoteDaemonControlOutboxError("corrupt", "eventId");
  let bytes: Uint8Array;
  try {
    bytes = decodeProtocolIdBase64Url(stored);
  } catch {
    throw new RemoteDaemonControlOutboxError("corrupt", "eventId encoding");
  }
  if (bytes.length !== 16) throw new RemoteDaemonControlOutboxError("corrupt", "eventId length");
  return bytes;
}

/**
 * Production Postgres reader over `RemoteDaemonControlOutbox`. Reads only
 * `controlSeq > afterControlSeq` rows for the exact `(instance, generation)`
 * scope; the high-water is the scope-wide `MAX(controlSeq)` so a daemon claiming
 * a future cursor is detectable by the gateway.
 */
export class PostgresRemoteDaemonControlOutboxStore implements RemoteDaemonControlOutboxStore {
  constructor(private readonly db: SqlClient) {}

  async readDaemonControlOutboxPage(
    input: ReadDaemonControlOutboxPageInput,
  ): Promise<RemoteDaemonControlOutboxPageV1> {
    // ONE statement (a single MVCC snapshot) reads both the scope-wide high-water
    // and the page, so a row committing between two reads can never yield a
    // `{events:[], truncated:false}` that falsely declares completion. The
    // high-water side always returns exactly one row (`COALESCE(MAX,0)`), so an
    // empty page still carries the true high-water for the gateway's 4409 check.
    let rows: Array<Record<string, unknown>>;
    try {
      rows = await this.db.$queryRawUnsafe<Array<Record<string, unknown>>>(
        `SELECT h."highWaterSeq" AS "highWaterSeq", s."controlSeq" AS "controlSeq", s."eventId" AS "eventId", s."controlEventJws" AS "controlEventJws", s."payloadDigest" AS "payloadDigest" FROM (SELECT COALESCE(MAX("controlSeq"), 0) AS "highWaterSeq" FROM remote_daemon_control_outbox WHERE "daemonInstanceProtocolId"=$1 AND "daemonCertificateGeneration"=$2::numeric) h LEFT JOIN LATERAL (SELECT "controlSeq","eventId","controlEventJws","payloadDigest" FROM remote_daemon_control_outbox WHERE "daemonInstanceProtocolId"=$1 AND "daemonCertificateGeneration"=$2::numeric AND "controlSeq">$3::numeric ORDER BY "controlSeq" ASC LIMIT $4) s ON true ORDER BY s."controlSeq" ASC NULLS LAST`,
        input.daemonInstanceProtocolId,
        input.daemonCertificateGeneration.toString(),
        input.afterControlSeq.toString(),
        REMOTE_DAEMON_CONTROL_OUTBOX_MAX_EVENTS + 1,
      );
    } catch (error) {
      if (error instanceof RemoteDaemonControlOutboxError) throw error;
      throw new RemoteDaemonControlOutboxError("unavailable");
    }
    // Row decoding is fail-closed: a malformed numeric/id column raises the typed
    // `corrupt` error (never an uncaught BigInt SyntaxError).
    try {
      const highWater = rows.length === 0 ? 0n : BigInt(String(rows[0]?.highWaterSeq ?? 0));
      const ordered = rows
        .filter((row) => row.controlSeq !== null && row.controlSeq !== undefined)
        .map((row): RemoteDaemonControlOutboxEventV1 => {
          const jws = row.controlEventJws;
          if (typeof jws !== "string" || jws.length === 0)
            throw new RemoteDaemonControlOutboxError("corrupt", "controlEventJws");
          const digest = row.payloadDigest;
          return {
            controlSeq: BigInt(String(row.controlSeq)),
            eventId: decodeEventId(row.eventId),
            controlEventJws: jws,
            ...(typeof digest === "string" ? { payloadDigest: digest } : {}),
          };
        });
      return buildPage(ordered, highWater);
    } catch (error) {
      if (error instanceof RemoteDaemonControlOutboxError) throw error;
      throw new RemoteDaemonControlOutboxError("corrupt", "row decode");
    }
  }
}

interface MemoryControlOutboxRow {
  controlSeq: bigint;
  eventId: Uint8Array;
  controlEventJws: string;
  payloadDigest?: string;
}

/**
 * Memory test double with page/cap semantics identical to the Postgres reader.
 * `append` is the test seam that mint (Postgres) fills in production.
 */
export class MemoryRemoteDaemonControlOutboxStore implements RemoteDaemonControlOutboxStore {
  private readonly scopes = new Map<string, MemoryControlOutboxRow[]>();

  private scopeKey(instanceProtocolId: string, certificateGeneration: bigint): string {
    return `${instanceProtocolId}/${certificateGeneration}`;
  }

  /** Insert one ordered outbox row for an instance generation (mirrors the mint append). */
  append(input: {
    daemonInstanceProtocolId: string;
    daemonCertificateGeneration: bigint;
    controlSeq: bigint;
    eventId: Uint8Array;
    controlEventJws: string;
    payloadDigest?: string;
  }): void {
    if (input.eventId.length !== 16 || input.eventId.every((byte) => byte === 0))
      throw new RemoteDaemonControlOutboxError("corrupt", "eventId must be nonzero 16 bytes");
    if (input.controlSeq < 1n)
      throw new RemoteDaemonControlOutboxError("corrupt", "controlSeq must be ≥1");
    // Parity with the Postgres reader, which rejects an empty stored JWS as
    // corrupt: mint never stores an empty control-event JWS, so neither store
    // may ever surface one for delivery.
    if (input.controlEventJws.length === 0)
      throw new RemoteDaemonControlOutboxError("corrupt", "controlEventJws must be non-empty");
    const key = this.scopeKey(input.daemonInstanceProtocolId, input.daemonCertificateGeneration);
    let rows = this.scopes.get(key);
    if (!rows) {
      rows = [];
      this.scopes.set(key, rows);
    }
    if (rows.some((row) => row.controlSeq === input.controlSeq))
      throw new RemoteDaemonControlOutboxError("corrupt", "duplicate controlSeq");
    rows.push({
      controlSeq: input.controlSeq,
      eventId: input.eventId.slice(),
      controlEventJws: input.controlEventJws,
      ...(input.payloadDigest !== undefined ? { payloadDigest: input.payloadDigest } : {}),
    });
    rows.sort((left, right) => (left.controlSeq < right.controlSeq ? -1 : 1));
  }

  async readDaemonControlOutboxPage(
    input: ReadDaemonControlOutboxPageInput,
  ): Promise<RemoteDaemonControlOutboxPageV1> {
    const rows =
      this.scopes.get(
        this.scopeKey(input.daemonInstanceProtocolId, input.daemonCertificateGeneration),
      ) ?? [];
    const highWater = rows.reduce((max, row) => (row.controlSeq > max ? row.controlSeq : max), 0n);
    const ordered = rows
      .filter((row) => row.controlSeq > input.afterControlSeq)
      .map(
        (row): RemoteDaemonControlOutboxEventV1 => ({
          controlSeq: row.controlSeq,
          eventId: row.eventId.slice(),
          controlEventJws: row.controlEventJws,
          ...(row.payloadDigest !== undefined ? { payloadDigest: row.payloadDigest } : {}),
        }),
      );
    return buildPage(ordered, highWater);
  }
}

/** Minimal Redis publisher seam (ioredis `publish` is compatible). */
export interface RemoteControlOutboxWakePublisher {
  publish(channel: string, message: string): Promise<unknown>;
}

/** The dedicated control-outbox wake channel for one instance generation. */
export function remoteDaemonControlOutboxWakeChannel(
  daemonInstanceProtocolId: string,
  daemonCertificateGeneration: bigint,
): string {
  return `${REMOTE_DAEMON_CONTROL_OUTBOX_WAKE_PREFIX}${daemonInstanceProtocolId}:${daemonCertificateGeneration}`;
}

/**
 * Publish a control-outbox append wake AFTER the mint transaction commits. The
 * payload is a signal plus a high-water hint only — never the control-event
 * bytes, which are read back from Postgres by every woken replica. Mint (the
 * only writer) calls this at its finalize site; this landing ships no mint path.
 */
export async function notifyDaemonControlOutboxAppend(
  redis: RemoteControlOutboxWakePublisher,
  args: {
    daemonInstanceProtocolId: string;
    daemonCertificateGeneration: bigint;
    highWaterSeq: bigint;
  },
): Promise<void> {
  await redis.publish(
    remoteDaemonControlOutboxWakeChannel(
      args.daemonInstanceProtocolId,
      args.daemonCertificateGeneration,
    ),
    JSON.stringify({
      daemonInstanceProtocolId: args.daemonInstanceProtocolId,
      daemonCertificateGeneration: args.daemonCertificateGeneration.toString(),
      highWaterSeq: args.highWaterSeq.toString(),
    }),
  );
}
