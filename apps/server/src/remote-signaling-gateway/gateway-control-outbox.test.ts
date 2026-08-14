import { MemoryRemoteDaemonControlOutboxStore } from "@flycockpit/api/lib/remote-daemon-control-outbox";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type WebSocket from "ws";
import {
  decodeControlReplayPageTrailer,
  encodeControlReplayRequest,
  encodeGatewayAck,
  FCRP_MAGIC,
  RemoteGatewayAckKind,
} from "./binary-codecs";
import { REMOTE_GATEWAY_CLOSE_CODE, REMOTE_GATEWAY_SUBPROTOCOL } from "./close-codes";
import {
  buildRingVerifier,
  connectWithQueue,
  makeIdentityRing,
  mintDaemonCertificate,
  request,
  signFcda,
  type TestIdentityRing,
} from "./identity-fixtures";
import { type GatewayTestEnv, startGatewayServer, waitForClose } from "./test-fixtures";

let env: GatewayTestEnv | undefined;

beforeEach(() => {
  env = undefined;
});

afterEach(async () => {
  vi.restoreAllMocks();
  if (env) await env.close();
  env = undefined;
});

const te = new TextEncoder();
const eid = (n: number): Uint8Array => {
  const bytes = new Uint8Array(16);
  bytes[15] = n & 0xff;
  bytes[14] = (n >> 8) & 0xff;
  return bytes;
};

interface AuthedControl {
  ws: WebSocket;
  queue: Awaited<ReturnType<typeof connectWithQueue>>["queue"];
  instanceId: string;
  certificateGeneration: bigint;
}

/** Authenticate a control socket end to end; resolve once auth has completed. */
async function authControl(
  target: GatewayTestEnv,
  ring: TestIdentityRing,
  options?: { lastControlSeq?: bigint; instanceId?: string; generation?: bigint },
): Promise<AuthedControl> {
  const cert = mintDaemonCertificate({
    ring: ring.ring,
    kid: ring.kid,
    ringPrivateKey: ring.privateKey,
    ...(options?.instanceId ? { instanceId: options.instanceId } : {}),
    ...(options?.generation ? { generation: options.generation } : {}),
  });
  const originalReadDiscovery = target.store.readDiscovery.bind(target.store);
  const authenticated = new Promise<void>((resolve) => {
    vi.spyOn(target.store, "readDiscovery").mockImplementation((...args) => {
      resolve();
      return originalReadDiscovery(...args);
    });
  });
  const { ws, queue } = await connectWithQueue(target.url, {
    subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.control,
  });
  const fcdc = await queue.next();
  ws.send(
    Buffer.from(
      signFcda({
        fcdcFrame: fcdc,
        certJws: cert.certJws,
        daemonPrivateKey: cert.daemonPrivateKey,
        instanceProtocolId: cert.instanceProtocolId,
        certificateGeneration: cert.certificateGeneration,
        ...(options?.lastControlSeq !== undefined
          ? { lastControlSeq: options.lastControlSeq }
          : {}),
      }),
    ),
  );
  await authenticated;
  return {
    ws,
    queue,
    instanceId: cert.instanceId,
    certificateGeneration: cert.certificateGeneration,
  };
}

function seedStore(
  store: MemoryRemoteDaemonControlOutboxStore,
  instanceId: string,
  generation: bigint,
  jwsBySeq: Record<number, string>,
) {
  for (const [seq, jws] of Object.entries(jwsBySeq))
    store.append({
      daemonInstanceProtocolId: instanceId,
      daemonCertificateGeneration: generation,
      controlSeq: BigInt(seq),
      eventId: eid(Number(seq)),
      controlEventJws: jws,
    });
}

function seedOutbox(
  target: GatewayTestEnv,
  instanceId: string,
  generation: bigint,
  jwsBySeq: Record<number, string>,
) {
  seedStore(target.controlOutbox, instanceId, generation, jwsBySeq);
}

function racedClose(ws: WebSocket, ms: number): Promise<{ closed: boolean; code?: number }> {
  return Promise.race([
    waitForClose(ws).then((closed) => ({ closed: true, code: closed.code })),
    new Promise<{ closed: false }>((resolve) => setTimeout(() => resolve({ closed: false }), ms)),
  ]);
}

describe("remote_gateway_control_outbox_live_delivery", () => {
  it("delivers appended control events as exact JWS bytes in controlSeq order", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const authed = await authControl(env, ring, { lastControlSeq: 0n });
    const jws1 = "eyJhbGciOiJFUzI1NiJ9.eyJzZXEiOjF9.sig-one";
    const jws2 = "eyJhbGciOiJFUzI1NiJ9.eyJzZXEiOjJ9.sig-two";
    seedOutbox(env, authed.instanceId, authed.certificateGeneration, { 1: jws1, 2: jws2 });
    env.wake.publishControlOutbox(authed.instanceId, authed.certificateGeneration);

    expect(Buffer.from(await authed.queue.next())).toEqual(Buffer.from(te.encode(jws1)));
    expect(Buffer.from(await authed.queue.next())).toEqual(Buffer.from(te.encode(jws2)));
    authed.ws.close();
  }, 15_000);
});

describe("remote_gateway_control_outbox_resume_from_last_control_seq", () => {
  it("delivers only controlSeq > lastControlSeq", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const instanceId = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
    }).instanceId;
    // Seed first so the initial post-auth drain resumes from lastControlSeq=2.
    seedOutbox(env, instanceId, 1n, { 1: "jws-1", 2: "jws-2", 3: "jws-3" });
    const authed = await authControl(env, ring, { lastControlSeq: 2n, instanceId });
    expect(Buffer.from(await authed.queue.next())).toEqual(Buffer.from(te.encode("jws-3")));
    // No earlier event is redelivered: a follow-up wake yields nothing new.
    env.wake.publishControlOutbox(instanceId, 1n);
    const outcome = await racedClose(authed.ws, 300);
    expect(outcome.closed).toBe(false);
    expect(authed.queue.length).toBe(0);
    authed.ws.close();
  }, 15_000);

  it("closes 4409 when lastControlSeq is above the outbox high-water", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const instanceId = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
    }).instanceId;
    seedOutbox(env, instanceId, 1n, { 1: "jws-1", 2: "jws-2" });
    const authed = await authControl(env, ring, { lastControlSeq: 5n, instanceId });
    const closed = await waitForClose(authed.ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.conflict_or_superseded);
  }, 15_000);
});

describe("remote_gateway_control_outbox_backpressure", () => {
  it("closes 4429 on the outbound ceiling and redelivers every unsent event on a recovered replica", async () => {
    const ring = makeIdentityRing();
    // Both replicas share one durable control outbox; only the tight-ceiling
    // replica A trips backpressure. Replica B models a recovered/roomy replica.
    const sharedOutbox = new MemoryRemoteDaemonControlOutboxStore();
    env = await startGatewayServer({
      daemonCertificateVerifier: buildRingVerifier(ring.ring),
      controlOutbox: sharedOutbox,
      policy: { backpressure: { maxUnackedEvents: 1 } },
    });
    const instanceId = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
    }).instanceId;
    // Seed the SHARED outbox the gateway actually reads (env.controlOutbox is a
    // distinct default store when controlOutbox is injected via overrides).
    seedStore(sharedOutbox, instanceId, 1n, { 1: "jws-1", 2: "jws-2", 3: "jws-3" });
    const authed = await authControl(env, ring, { lastControlSeq: 0n, instanceId });
    // Attach the close listener synchronously (no intervening macrotask) so the
    // backpressure close raised by the initial drain can never be missed.
    const closePromise = waitForClose(authed.ws);
    // The drain sends jws-1 (pendingSends 0→1); jws-2 trips the unacked ceiling
    // of one before jws-1's flush lands in the synchronous send loop → 4429.
    // The cursor only advanced for jws-1, so jws-2/jws-3 are never handed to
    // ws.send and stay committed in the outbox.
    expect(Buffer.from(await authed.queue.next())).toEqual(Buffer.from(te.encode("jws-1")));
    const closed = await closePromise;
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure);

    // Nothing was permanently dropped. The daemon only received jws-1 before the
    // 4429, so it reconnects reporting lastControlSeq=1. A recovered replica with
    // headroom over the SAME durable outbox must redeliver exactly the unsent
    // tail (jws-2, jws-3) — and must NOT resend jws-1. Resuming from the received
    // cursor (not 0) is what proves the tail was neither dropped nor skipped: if
    // replica A had wrongly advanced past jws-2/jws-3, they would be missing here.
    const replicaB = await startGatewayServer({
      daemonCertificateVerifier: buildRingVerifier(ring.ring),
      controlOutbox: sharedOutbox,
    });
    try {
      const reconnect = await authControl(replicaB, ring, { lastControlSeq: 1n, instanceId });
      expect(Buffer.from(await reconnect.queue.next())).toEqual(Buffer.from(te.encode("jws-2")));
      expect(Buffer.from(await reconnect.queue.next())).toEqual(Buffer.from(te.encode("jws-3")));
      reconnect.ws.close();
    } finally {
      await replicaB.close();
    }
  }, 15_000);
});

describe("remote_gateway_control_post_auth_inbound_demux", () => {
  it("accepts an exact 26-byte kind-2 control-delivery ACK without closing", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const instanceId = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
    }).instanceId;
    seedOutbox(env, instanceId, 1n, { 1: "jws-1" });
    const authed = await authControl(env, ring, { lastControlSeq: 1n, instanceId });
    authed.ws.send(
      Buffer.from(
        encodeGatewayAck({
          kind: RemoteGatewayAckKind.control_event_delivery,
          commandId: eid(1),
          committedSequence: 1n,
        }),
      ),
    );
    const outcome = await racedClose(authed.ws, 300);
    expect(outcome.closed).toBe(false);
    authed.ws.close();
  }, 15_000);

  it("answers FCRQ with N exact JWS frames and a terminal FCRP trailer", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const instanceId = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
    }).instanceId;
    seedOutbox(env, instanceId, 1n, { 1: "jws-1", 2: "jws-2", 3: "jws-3" });
    // Auth at high-water so live delivery is idle and only the FCRQ replay flows.
    const authed = await authControl(env, ring, { lastControlSeq: 3n, instanceId });
    authed.ws.send(Buffer.from(encodeControlReplayRequest({ afterControlSeq: 0n })));

    expect(Buffer.from(await authed.queue.next())).toEqual(Buffer.from(te.encode("jws-1")));
    expect(Buffer.from(await authed.queue.next())).toEqual(Buffer.from(te.encode("jws-2")));
    expect(Buffer.from(await authed.queue.next())).toEqual(Buffer.from(te.encode("jws-3")));
    const trailer = await authed.queue.next();
    expect(trailer.subarray(0, 4).toString("ascii")).toBe(FCRP_MAGIC);
    expect(decodeControlReplayPageTrailer(new Uint8Array(trailer))).toEqual({
      highWaterSeq: 3n,
      truncated: false,
      eventCount: 3,
    });
    authed.ws.close();
  }, 15_000);

  it("answers an empty FCRQ page with a lone FCRP (eventCount 0)", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const instanceId = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
    }).instanceId;
    seedOutbox(env, instanceId, 1n, { 1: "jws-1", 2: "jws-2" });
    const authed = await authControl(env, ring, { lastControlSeq: 2n, instanceId });
    authed.ws.send(Buffer.from(encodeControlReplayRequest({ afterControlSeq: 2n })));
    const trailer = await authed.queue.next();
    expect(decodeControlReplayPageTrailer(new Uint8Array(trailer))).toEqual({
      highWaterSeq: 2n,
      truncated: false,
      eventCount: 0,
    });
    authed.ws.close();
  }, 15_000);

  it("keeps FCSE routed to the signaling commit path on a control socket", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const commit = vi.spyOn(env.store, "commit");
    const authed = await authControl(env, ring, { lastControlSeq: 0n });
    // A daemon-role (3) FCSE reaches the signaling path even absent an attempt.
    authed.ws.send(Buffer.from(request(2, 3, 2, 1)));
    await vi.waitFor(() => expect(commit).toHaveBeenCalled());
  }, 15_000);

  it("closes 4400 on inbound FCRC and never appends", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const authed = await authControl(env, ring, { lastControlSeq: 0n });
    const fcrc = new Uint8Array(98);
    fcrc.set(te.encode("FCRC"), 0);
    fcrc[4] = 1;
    authed.ws.send(Buffer.from(fcrc));
    const closed = await waitForClose(authed.ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
    // Behavioral proof (not just the close code): the inbound FCRC was NEVER
    // appended to the outbox — the scope stays empty with high-water 0.
    const after = await env.controlOutbox.readDaemonControlOutboxPage({
      daemonInstanceProtocolId: authed.instanceId,
      daemonCertificateGeneration: authed.certificateGeneration,
      afterControlSeq: 0n,
    });
    expect(after.events).toEqual([]);
    expect(after.highWaterSeq).toBe(0n);
  }, 15_000);

  it("closes 4400 on an unknown magic", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const authed = await authControl(env, ring, { lastControlSeq: 0n });
    const unknown = new Uint8Array(12);
    unknown.set(te.encode("FCZZ"), 0);
    authed.ws.send(Buffer.from(unknown));
    const closed = await waitForClose(authed.ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
  }, 15_000);
});
