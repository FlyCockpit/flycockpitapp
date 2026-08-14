import { encodeProtocolIdBase64Url } from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import type { SqlClient } from "./remote-authority-storage";
import {
  MemoryRemoteDaemonControlOutboxStore,
  PostgresRemoteDaemonControlOutboxStore,
  REMOTE_DAEMON_CONTROL_OUTBOX_MAX_BYTES,
  REMOTE_DAEMON_CONTROL_OUTBOX_MAX_EVENTS,
  RemoteDaemonControlOutboxError,
  remoteDaemonControlOutboxWakeChannel,
} from "./remote-daemon-control-outbox";

const INSTANCE = encodeProtocolIdBase64Url(new Uint8Array(16).fill(3));
const OTHER_INSTANCE = encodeProtocolIdBase64Url(new Uint8Array(16).fill(9));

function eventId(n: number): Uint8Array {
  const bytes = new Uint8Array(16);
  bytes[15] = n & 0xff;
  bytes[14] = (n >> 8) & 0xff;
  return bytes;
}

function seed(
  store: MemoryRemoteDaemonControlOutboxStore,
  count: number,
  options?: { generation?: bigint; jws?: (seq: number) => string },
) {
  for (let seq = 1; seq <= count; seq++)
    store.append({
      daemonInstanceProtocolId: INSTANCE,
      daemonCertificateGeneration: options?.generation ?? 7n,
      controlSeq: BigInt(seq),
      eventId: eventId(seq),
      controlEventJws: options?.jws ? options.jws(seq) : `jws-${seq}`,
      payloadDigest: `digest-${seq}`,
    });
}

describe("remote_daemon_control_outbox_read_page", () => {
  it("returns rows in controlSeq ASC order from afterControlSeq=0", async () => {
    const store = new MemoryRemoteDaemonControlOutboxStore();
    seed(store, 3);
    const page = await store.readDaemonControlOutboxPage({
      daemonInstanceProtocolId: INSTANCE,
      daemonCertificateGeneration: 7n,
      afterControlSeq: 0n,
    });
    expect(page.events.map((event) => event.controlSeq)).toEqual([1n, 2n, 3n]);
    expect(page.events[0]?.controlEventJws).toBe("jws-1");
    expect(page.events[0]?.eventId).toEqual(eventId(1));
    expect(page.events[0]?.payloadDigest).toBe("digest-1");
    expect(page.highWaterSeq).toBe(3n);
    expect(page.truncated).toBe(false);
  });

  it("applies afterControlSeq exclusively", async () => {
    const store = new MemoryRemoteDaemonControlOutboxStore();
    seed(store, 5);
    const page = await store.readDaemonControlOutboxPage({
      daemonInstanceProtocolId: INSTANCE,
      daemonCertificateGeneration: 7n,
      afterControlSeq: 2n,
    });
    expect(page.events.map((event) => event.controlSeq)).toEqual([3n, 4n, 5n]);
    expect(page.highWaterSeq).toBe(5n);
    expect(page.truncated).toBe(false);
  });

  it("caps the page at 64 events and reports truncated", async () => {
    const store = new MemoryRemoteDaemonControlOutboxStore();
    seed(store, REMOTE_DAEMON_CONTROL_OUTBOX_MAX_EVENTS + 6);
    const page = await store.readDaemonControlOutboxPage({
      daemonInstanceProtocolId: INSTANCE,
      daemonCertificateGeneration: 7n,
      afterControlSeq: 0n,
    });
    expect(page.events.length).toBe(REMOTE_DAEMON_CONTROL_OUTBOX_MAX_EVENTS);
    expect(page.events.at(-1)?.controlSeq).toBe(BigInt(REMOTE_DAEMON_CONTROL_OUTBOX_MAX_EVENTS));
    expect(page.highWaterSeq).toBe(BigInt(REMOTE_DAEMON_CONTROL_OUTBOX_MAX_EVENTS + 6));
    expect(page.truncated).toBe(true);
  });

  it("shrinks event count to hold the 512 KiB aggregate byte cap", async () => {
    const store = new MemoryRemoteDaemonControlOutboxStore();
    // Each JWS is ~200 KiB; two fit (400 KiB), the third would cross 512 KiB.
    const big = "a".repeat(200 * 1024);
    seed(store, 3, { jws: () => big });
    const page = await store.readDaemonControlOutboxPage({
      daemonInstanceProtocolId: INSTANCE,
      daemonCertificateGeneration: 7n,
      afterControlSeq: 0n,
    });
    expect(page.events.length).toBe(2);
    expect(page.highWaterSeq).toBe(3n);
    expect(page.truncated).toBe(true);
  });

  it("fails closed (corrupt) on a single JWS larger than 512 KiB", async () => {
    const store = new MemoryRemoteDaemonControlOutboxStore();
    store.append({
      daemonInstanceProtocolId: INSTANCE,
      daemonCertificateGeneration: 7n,
      controlSeq: 1n,
      eventId: eventId(1),
      controlEventJws: "a".repeat(REMOTE_DAEMON_CONTROL_OUTBOX_MAX_BYTES + 1),
    });
    await expect(
      store.readDaemonControlOutboxPage({
        daemonInstanceProtocolId: INSTANCE,
        daemonCertificateGeneration: 7n,
        afterControlSeq: 0n,
      }),
    ).rejects.toBeInstanceOf(RemoteDaemonControlOutboxError);
  });

  it("returns highWaterSeq 0 for an empty scope so a future cursor is a conflict", async () => {
    const store = new MemoryRemoteDaemonControlOutboxStore();
    const page = await store.readDaemonControlOutboxPage({
      daemonInstanceProtocolId: INSTANCE,
      daemonCertificateGeneration: 7n,
      afterControlSeq: 4n,
    });
    expect(page.events).toEqual([]);
    // Not `afterControlSeq`: echoing the claim would hide that the daemon
    // reported a cursor (4) above the real high-water (0) → the gateway's
    // `cursor > highWater` 4409 check must still fire.
    expect(page.highWaterSeq).toBe(0n);
    expect(page.truncated).toBe(false);
  });

  it("keeps generations and instances disjoint", async () => {
    const store = new MemoryRemoteDaemonControlOutboxStore();
    seed(store, 3, { generation: 7n });
    seed(store, 2, { generation: 8n });
    store.append({
      daemonInstanceProtocolId: OTHER_INSTANCE,
      daemonCertificateGeneration: 7n,
      controlSeq: 1n,
      eventId: eventId(50),
      controlEventJws: "other",
    });
    const gen8 = await store.readDaemonControlOutboxPage({
      daemonInstanceProtocolId: INSTANCE,
      daemonCertificateGeneration: 8n,
      afterControlSeq: 0n,
    });
    expect(gen8.events.map((event) => event.controlSeq)).toEqual([1n, 2n]);
    expect(gen8.highWaterSeq).toBe(2n);
  });

  it("reports a max below a future afterControlSeq (conflict signal)", async () => {
    const store = new MemoryRemoteDaemonControlOutboxStore();
    seed(store, 3);
    const page = await store.readDaemonControlOutboxPage({
      daemonInstanceProtocolId: INSTANCE,
      daemonCertificateGeneration: 7n,
      afterControlSeq: 9n,
    });
    expect(page.events).toEqual([]);
    expect(page.highWaterSeq).toBe(3n);
    expect(page.highWaterSeq < 9n).toBe(true);
  });
});

describe("remote_daemon_control_outbox_wake_channel", () => {
  it("scopes the wake channel to the instance generation", () => {
    expect(remoteDaemonControlOutboxWakeChannel(INSTANCE, 7n)).toBe(
      `flycockpit:remote-control:outbox-wake:${INSTANCE}:7`,
    );
  });
});

describe("remote_daemon_control_outbox_read_page: Postgres reader", () => {
  // Models the single LEFT JOIN LATERAL query: every result row carries the
  // COALESCE(MAX,0) high-water, and an empty page still returns one high-water
  // row with null page columns.
  function fakeSql(
    rows: Array<Record<string, unknown>>,
    max: bigint | null,
  ): { client: SqlClient; queries: string[] } {
    const queries: string[] = [];
    const highWaterSeq = max ?? 0n;
    const client = {
      async $queryRawUnsafe<T>(query: string): Promise<T> {
        queries.push(query);
        const page = rows.slice(0, REMOTE_DAEMON_CONTROL_OUTBOX_MAX_EVENTS + 1);
        if (page.length === 0)
          return [
            {
              highWaterSeq,
              controlSeq: null,
              eventId: null,
              controlEventJws: null,
              payloadDigest: null,
            },
          ] as unknown as T;
        return page.map((row) => ({ highWaterSeq, ...row })) as unknown as T;
      },
    } as unknown as SqlClient;
    return { client, queries };
  }

  it("reads only the daemon control outbox table and maps rows through the caps", async () => {
    const rows = [1, 2, 3].map((seq) => ({
      controlSeq: seq.toString(),
      eventId: encodeProtocolIdBase64Url(eventId(seq)),
      controlEventJws: `jws-${seq}`,
      payloadDigest: `digest-${seq}`,
    }));
    const { client, queries } = fakeSql(rows, 5n);
    const store = new PostgresRemoteDaemonControlOutboxStore(client);
    const page = await store.readDaemonControlOutboxPage({
      daemonInstanceProtocolId: INSTANCE,
      daemonCertificateGeneration: 7n,
      afterControlSeq: 0n,
    });
    expect(page.events.map((event) => event.controlSeq)).toEqual([1n, 2n, 3n]);
    expect(page.events[0]?.eventId).toEqual(eventId(1));
    expect(page.highWaterSeq).toBe(5n);
    // High-water 5 is above the last returned row (3) → more rows remain.
    expect(page.truncated).toBe(true);
    for (const query of queries) {
      expect(query).toContain("remote_daemon_control_outbox");
      expect(query).not.toContain("remote_authority_control_outbox");
    }
  });

  it("returns highWaterSeq 0 when the scope is empty (future cursor is a conflict)", async () => {
    const { client } = fakeSql([], null);
    const store = new PostgresRemoteDaemonControlOutboxStore(client);
    const page = await store.readDaemonControlOutboxPage({
      daemonInstanceProtocolId: INSTANCE,
      daemonCertificateGeneration: 7n,
      afterControlSeq: 2n,
    });
    expect(page.events).toEqual([]);
    expect(page.highWaterSeq).toBe(0n);
    expect(page.truncated).toBe(false);
  });
});
