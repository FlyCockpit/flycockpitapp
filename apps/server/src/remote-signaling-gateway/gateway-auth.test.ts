/**
 * Daemon control authentication (FCDA), client admission (FCSA), the per-device
 * signal-socket lease cap, and control-socket discovery/presence — driven end to
 * end against the real gateway, the real `MemoryRemoteSignalingAttemptStore`, and
 * the production `RingDaemonCertificateVerifier` over an in-test identity-CA ring.
 *
 * Every negative asserts the exact 4401/4409 close the gateway must send; nothing
 * here fakes the verifier or the store, so a missing check really fails.
 */
import {
  MemoryRemoteSignalingAttemptStore,
  REMOTE_SIGNALING_ADMISSION_TICKET_TTL_MS,
} from "@flycockpit/api/lib/remote-signaling-store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import WebSocket from "ws";
import { encodeFcsaFrame } from "./binary-codecs";
import { REMOTE_GATEWAY_CLOSE_CODE, REMOTE_GATEWAY_SUBPROTOCOL } from "./close-codes";
import {
  admitSignalSocket,
  buildRingVerifier,
  CONFIGURED_ORIGIN,
  clientAdmissionProofPayload,
  connectWithQueue,
  createInput,
  id,
  makeIdentityRing,
  mintDaemonCertificate,
  seedDaemonOfferedTicket,
  sha256Bytes,
  signFcda,
} from "./identity-fixtures";
import { type GatewayTestEnv, startGatewayServer, waitForClose } from "./test-fixtures";
import { InMemoryRemoteSignalingWakeSubscription } from "./wake-subscription";

let env: GatewayTestEnv | undefined;

beforeEach(() => {
  env = undefined;
});

afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  if (env) await env.close();
  env = undefined;
});

/** Connect a control socket and return it plus the received 53-byte FCDC challenge. */
async function connectControl(target: GatewayTestEnv) {
  const { ws, queue } = await connectWithQueue(target.url, {
    subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.control,
  });
  const fcdc = await queue.next();
  return { ws, queue, fcdc };
}

/** Race a close against a window; resolves `{closed:false}` if the socket stays open. */
function racedClose(ws: WebSocket, ms: number): Promise<{ closed: boolean; code?: number }> {
  return Promise.race([
    waitForClose(ws).then((closed) => ({ closed: true, code: closed.code })),
    new Promise<{ closed: false }>((resolve) => setTimeout(() => resolve({ closed: false }), ms)),
  ]);
}

function flipChar(value: string, index: number): string {
  const replacement = value[index] === "A" ? "B" : "A";
  return value.slice(0, index) + replacement + value.slice(index + 1);
}

async function attemptSignalAdmission(
  target: GatewayTestEnv,
  input: { ticketId: Uint8Array; secret: Uint8Array; admissionProof: Uint8Array; origin?: string },
) {
  const { ws, queue } = await connectWithQueue(target.url, {
    subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
    headers: input.origin ? { origin: input.origin } : undefined,
  });
  ws.send(
    Buffer.from(
      encodeFcsaFrame({
        ticketId: input.ticketId,
        ticketSecret: input.secret,
        admissionProof: input.admissionProof,
      }),
    ),
  );
  return { ws, queue };
}

describe("remote_gateway_daemon_auth", () => {
  it("closes 4401 when the FCDA signature does not verify under the certificate key", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const cert = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
    });
    const { ws, queue, fcdc } = await connectControl(env);
    const frame = signFcda({
      fcdcFrame: fcdc,
      certJws: cert.certJws,
      daemonPrivateKey: cert.daemonPrivateKey,
      instanceProtocolId: cert.instanceProtocolId,
      certificateGeneration: cert.certificateGeneration,
    });
    frame[frame.length - 1] = frame[frame.length - 1]! ^ 0x01; // corrupt the P-256 signature
    ws.send(Buffer.from(frame));
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
    // Only the close frame — no post-challenge data frame was delivered.
    expect(queue.length).toBe(0);
  });

  it("keeps a correctly minted and signed control socket open (no auth close)", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const cert = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
    });
    const { ws, fcdc } = await connectControl(env);
    ws.send(
      Buffer.from(
        signFcda({
          fcdcFrame: fcdc,
          certJws: cert.certJws,
          daemonPrivateKey: cert.daemonPrivateKey,
          instanceProtocolId: cert.instanceProtocolId,
          certificateGeneration: cert.certificateGeneration,
        }),
      ),
    );
    const outcome = await racedClose(ws, 400);
    expect(outcome.closed).toBe(false);
    expect(ws.readyState).toBe(WebSocket.OPEN);
  });

  it("closes 4401 when the preimage is signed for a different origin (cross-domain)", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const cert = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
    });
    const { ws, fcdc } = await connectControl(env);
    ws.send(
      Buffer.from(
        signFcda({
          fcdcFrame: fcdc,
          certJws: cert.certJws,
          daemonPrivateKey: cert.daemonPrivateKey,
          instanceProtocolId: cert.instanceProtocolId,
          certificateGeneration: cert.certificateGeneration,
          configuredOrigin: "https://evil.test",
        }),
      ),
    );
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  });

  it("closes 4401 when one certificate JWS byte is tampered", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const cert = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
    });
    const tamperedJws = flipChar(cert.certJws, Math.floor(cert.certJws.length / 2));
    const { ws, fcdc } = await connectControl(env);
    ws.send(
      Buffer.from(
        signFcda({
          fcdcFrame: fcdc,
          certJws: tamperedJws,
          daemonPrivateKey: cert.daemonPrivateKey,
          instanceProtocolId: cert.instanceProtocolId,
          certificateGeneration: cert.certificateGeneration,
        }),
      ),
    );
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  });

  it("closes 4401 when the certificate kid is not in the installed ring", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const cert = mintDaemonCertificate({
      ring: ring.ring,
      kid: "unknown-kid-not-in-ring",
      ringPrivateKey: ring.privateKey,
    });
    const { ws, fcdc } = await connectControl(env);
    ws.send(
      Buffer.from(
        signFcda({
          fcdcFrame: fcdc,
          certJws: cert.certJws,
          daemonPrivateKey: cert.daemonPrivateKey,
          instanceProtocolId: cert.instanceProtocolId,
          certificateGeneration: cert.certificateGeneration,
        }),
      ),
    );
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  });

  it("closes 4401 when the certificate is expired", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const cert = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
      iat: 0n,
      exp: 1n,
    });
    const { ws, fcdc } = await connectControl(env);
    ws.send(
      Buffer.from(
        signFcda({
          fcdcFrame: fcdc,
          certJws: cert.certJws,
          daemonPrivateKey: cert.daemonPrivateKey,
          instanceProtocolId: cert.instanceProtocolId,
          certificateGeneration: cert.certificateGeneration,
        }),
      ),
    );
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  });

  it("closes 4401 when the subject is a client (subjectKind 1), not a daemon", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const cert = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
      subjectKind: 1,
    });
    const { ws, fcdc } = await connectControl(env);
    ws.send(
      Buffer.from(
        signFcda({
          fcdcFrame: fcdc,
          certJws: cert.certJws,
          daemonPrivateKey: cert.daemonPrivateKey,
          instanceProtocolId: cert.instanceProtocolId,
          certificateGeneration: cert.certificateGeneration,
        }),
      ),
    );
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  });

  it("closes 4401 when the certificate is signed by a different, uninstalled ring", async () => {
    const installed = makeIdentityRing();
    const foreign = makeIdentityRing();
    env = await startGatewayServer({
      daemonCertificateVerifier: buildRingVerifier(installed.ring),
    });
    const cert = mintDaemonCertificate({
      ring: foreign.ring,
      kid: foreign.kid,
      ringPrivateKey: foreign.privateKey,
    });
    const { ws, fcdc } = await connectControl(env);
    ws.send(
      Buffer.from(
        signFcda({
          fcdcFrame: fcdc,
          certJws: cert.certJws,
          daemonPrivateKey: cert.daemonPrivateKey,
          instanceProtocolId: cert.instanceProtocolId,
          certificateGeneration: cert.certificateGeneration,
        }),
      ),
    );
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  });
});

describe("remote_gateway_client_admission", () => {
  it("admits a client with a matching ticket and advances the attempt to admitted", async () => {
    env = await startGatewayServer();
    const admitted = await admitSignalSocket(env);
    expect(admitted.initialDeliveries).toHaveLength(2);

    const page = await env.store.read(createInput.daemonInstanceId, admitted.child, 0n);
    expect(page.kind).toBe("events");
    if (page.kind === "events") {
      expect(page.events.map((event) => event.request.eventKind)).toEqual([1, 2, 3]);
      const admission = page.events.find((event) => event.request.eventKind === 3);
      // Actor is server-derived from the consumed ticket, not the client bytes.
      expect(admission?.actor).toEqual({ role: "client", actor: "attach-1", generation: 5n });
    }

    const outcome = await racedClose(admitted.ws, 300);
    expect(outcome.closed).toBe(false);
  });

  it("closes 4401 on a wrong ticket secret", async () => {
    env = await startGatewayServer();
    const { ticketId, proofBytes } = await seedDaemonOfferedTicket(env.store);
    const { ws } = await attemptSignalAdmission(env, {
      ticketId,
      secret: new Uint8Array(32).fill(3),
      admissionProof: proofBytes,
      origin: CONFIGURED_ORIGIN,
    });
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  });

  it("closes 4401 when the socket origin class does not match the ticket", async () => {
    env = await startGatewayServer();
    // Ticket bound to native_no_origin, but the socket presents a browser Origin.
    const { ticketId, secret, proofBytes } = await seedDaemonOfferedTicket(env.store, {
      originClass: "native_no_origin",
    });
    const { ws } = await attemptSignalAdmission(env, {
      ticketId,
      secret,
      admissionProof: proofBytes,
      origin: CONFIGURED_ORIGIN,
    });
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  });

  it("closes 4401 when the admission proof does not match the ticket-bound digest", async () => {
    env = await startGatewayServer();
    const { ticketId, secret, proofBytes } = await seedDaemonOfferedTicket(env.store, {
      admissionProofSha256: sha256Bytes(new Uint8Array(16).fill(2)),
    });
    const { ws } = await attemptSignalAdmission(env, {
      ticketId,
      secret,
      admissionProof: proofBytes,
      origin: CONFIGURED_ORIGIN,
    });
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  });

  it("closes 4401 on an expired ticket under an injected store clock", async () => {
    const wake = new InMemoryRemoteSignalingWakeSubscription();
    let nowMs = 1_000;
    const store = new MemoryRemoteSignalingAttemptStore(
      () => nowMs,
      (out) => out.set(crypto.getRandomValues(new Uint8Array(out.length))),
      (route) => wake.publishAttempt(route),
    );
    env = await startGatewayServer({ store, wake });
    const { ticketId, secret, proofBytes } = await seedDaemonOfferedTicket(store);
    nowMs += REMOTE_SIGNALING_ADMISSION_TICKET_TTL_MS + 1;
    const { ws } = await attemptSignalAdmission(env, {
      ticketId,
      secret,
      admissionProof: proofBytes,
      origin: CONFIGURED_ORIGIN,
    });
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  });

  it("closes 4401 when the same consumed ticket is replayed for a distinct admission", async () => {
    env = await startGatewayServer();
    const admitted = await admitSignalSocket(env);
    // A second socket presents the same ticket with a different proof (distinct
    // proofJti → no idempotent replay). The ticket is already consumed → 4401.
    const distinctProof = clientAdmissionProofPayload({ proofJti: id(200) });
    const { ws } = await attemptSignalAdmission(env, {
      ticketId: admitted.ticketId,
      secret: admitted.secret,
      admissionProof: distinctProof,
      origin: CONFIGURED_ORIGIN,
    });
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  });
});

describe("remote_gateway_client_admission_lease_cap", () => {
  it("closes the third concurrent admit for one attachment with 4409", async () => {
    env = await startGatewayServer();
    const attachment = "attach-shared";
    await admitSignalSocket(env, { child: id(1), deviceAttachmentId: attachment });
    await admitSignalSocket(env, { child: id(2), deviceAttachmentId: attachment });
    // Third admit for the same device attachment exceeds the store's lease cap (2).
    const { ticketId, secret, proofBytes } = await seedDaemonOfferedTicket(env.store, {
      child: id(3),
      deviceAttachmentId: attachment,
    });
    const { ws } = await attemptSignalAdmission(env, {
      ticketId,
      secret,
      admissionProof: proofBytes,
      origin: CONFIGURED_ORIGIN,
    });
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.conflict_or_superseded);
  });
});

describe("remote_gateway_control_discovery", () => {
  it("allocates a monotonic control socket generation and authenticates a wake lease", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const allocateSpy = vi.spyOn(env.store, "allocateControlSocketGeneration");
    const authenticateSpy = vi.spyOn(env.store, "authenticateInstanceWake");
    const cert = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
    });
    const { ws, fcdc } = await connectControl(env);
    ws.send(
      Buffer.from(
        signFcda({
          fcdcFrame: fcdc,
          certJws: cert.certJws,
          daemonPrivateKey: cert.daemonPrivateKey,
          instanceProtocolId: cert.instanceProtocolId,
          certificateGeneration: cert.certificateGeneration,
        }),
      ),
    );
    await vi.waitFor(() => expect(allocateSpy).toHaveBeenCalled());
    expect(allocateSpy).toHaveBeenCalledWith(cert.instanceId, cert.certificateGeneration);
    expect(await allocateSpy.mock.results[0]?.value).toBe(1n);
    expect(authenticateSpy).toHaveBeenCalled();
    expect(ws.readyState).toBe(WebSocket.OPEN);
  });

  it("renews the instance wake lease on the 15s presence timer", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const cert = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
    });
    // Resolve on the first discovery read, which the gateway performs strictly
    // AFTER it creates the presence interval — so advancing timers can fire it.
    const originalReadDiscovery = env.store.readDiscovery.bind(env.store);
    const authenticated = new Promise<void>((resolve) => {
      vi.spyOn(env!.store, "readDiscovery").mockImplementation((...args) => {
        resolve();
        return originalReadDiscovery(...args);
      });
    });
    const { ws, fcdc } = await connectControl(env);
    // Fake only the interval APIs so real WebSocket I/O keeps working.
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    ws.send(
      Buffer.from(
        signFcda({
          fcdcFrame: fcdc,
          certJws: cert.certJws,
          daemonPrivateKey: cert.daemonPrivateKey,
          instanceProtocolId: cert.instanceProtocolId,
          certificateGeneration: cert.certificateGeneration,
        }),
      ),
    );
    await authenticated;
    const renewSpy = vi.spyOn(env.store, "renewInstanceWake");
    expect(renewSpy).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(15_000);
    expect(renewSpy).toHaveBeenCalled();
  });
});
