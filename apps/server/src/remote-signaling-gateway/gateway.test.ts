import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import WebSocket from "ws";
import { encodeFcsaFrame } from "./binary-codecs";
import {
  REMOTE_GATEWAY_CLOSE_CODE,
  REMOTE_GATEWAY_CLOSE_REASON,
  REMOTE_GATEWAY_SIGNAL_LEASE_RENEWAL_MS,
  REMOTE_GATEWAY_SUBPROTOCOL,
  REMOTE_GATEWAY_WS_PATH,
} from "./close-codes";
import {
  actor,
  admitSignalSocket,
  buildRingVerifier,
  CONFIGURED_ORIGIN,
  connectWithQueue,
  createInput,
  id,
  makeIdentityRing,
  mintDaemonCertificate,
  request,
  sha256Bytes,
  signFcda,
  type TestIdentityRing,
} from "./identity-fixtures";
import { connectWs, type GatewayTestEnv, startGatewayServer, waitForClose } from "./test-fixtures";

let env: GatewayTestEnv | undefined;

beforeEach(() => {
  env = undefined;
});

afterEach(async () => {
  vi.restoreAllMocks();
  if (env) await env.close();
  env = undefined;
});

describe("remote_gateway_upgrade_and_binary_contract", () => {
  it("rejects wrong path", async () => {
    env = await startGatewayServer();
    const result = await Promise.race([
      connectWs(env.url.replace(REMOTE_GATEWAY_WS_PATH, "/wrong-path"), {
        subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      }).then(
        (ws) => ({ kind: "open" as const, ws }),
        () => ({ kind: "error" as const }),
      ),
      new Promise<{ kind: "timeout" }>((resolve) =>
        setTimeout(() => resolve({ kind: "timeout" }), 2_000),
      ),
    ]);
    expect(result.kind).not.toBe("open");
  }, 10_000);

  it("rejects missing subprotocol", async () => {
    env = await startGatewayServer();
    await expect(connectWs(env.url)).rejects.toThrow();
  });

  it("rejects unknown subprotocol", async () => {
    env = await startGatewayServer();
    await expect(connectWs(env.url, { subprotocol: "flycockpit.unknown.v1" })).rejects.toThrow();
  });

  it("rejects an offer of two subprotocols with 400", async () => {
    env = await startGatewayServer();
    await expect(
      connectWs(env.url, {
        subprotocol: [REMOTE_GATEWAY_SUBPROTOCOL.signal, REMOTE_GATEWAY_SUBPROTOCOL.control],
        headers: { origin: "https://app.example.test" },
      }),
    ).rejects.toThrow();
  });

  it("accepts signal subprotocol and echoes exactly the offered subprotocol", async () => {
    env = await startGatewayServer();
    const ws = await connectWs(env.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: "https://app.example.test" },
    });
    expect(ws.readyState).toBe(WebSocket.OPEN);
    expect(ws.protocol).toBe(REMOTE_GATEWAY_SUBPROTOCOL.signal);
    ws.close();
  });

  it("accepts control subprotocol (no origin)", async () => {
    env = await startGatewayServer();
    const ws = await connectWs(env.url, { subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.control });
    expect(ws.readyState).toBe(WebSocket.OPEN);
    expect(ws.protocol).toBe(REMOTE_GATEWAY_SUBPROTOCOL.control);
    ws.close();
  });

  it("rejects control subprotocol with present Origin", async () => {
    env = await startGatewayServer();
    await expect(
      connectWs(env.url, {
        subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.control,
        headers: { origin: "https://app.example.test" },
      }),
    ).rejects.toThrow();
  });

  it("rejects signal with wrong origin", async () => {
    env = await startGatewayServer();
    await expect(
      connectWs(env.url, {
        subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
        headers: { origin: "https://evil.test" },
      }),
    ).rejects.toThrow();
  });

  it("rejects signal with null origin", async () => {
    env = await startGatewayServer();
    await expect(
      connectWs(env.url, {
        subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
        headers: { origin: "null" },
      }),
    ).rejects.toThrow();
  });

  it("rejects compression extension", async () => {
    env = await startGatewayServer();
    await expect(
      new Promise<WebSocket>((resolve, reject) => {
        const ws = new WebSocket(env!.url, REMOTE_GATEWAY_SUBPROTOCOL.signal, {
          headers: { origin: "https://app.example.test" },
          perMessageDeflate: true,
        });
        ws.once("open", () => resolve(ws));
        ws.once("error", reject);
      }),
    ).rejects.toThrow();
  });

  it("closes text frames with 4400", async () => {
    env = await startGatewayServer();
    const ws = await connectWs(env.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: "https://app.example.test" },
    });
    ws.send("text frame", { binary: false });
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
    expect(closed.reason).toBe(REMOTE_GATEWAY_CLOSE_REASON[4400]);
  });

  it("closes with authentication_timeout after the pre-auth deadline", async () => {
    env = await startGatewayServer();
    const ws = await connectWs(env.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: "https://app.example.test" },
    });
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_timeout);
    expect(closed.reason).toBe(REMOTE_GATEWAY_CLOSE_REASON[4408]);
  }, 10_000);

  it("sends the exact 53-byte FCDC challenge on control connection", async () => {
    env = await startGatewayServer();
    const challenge = await new Promise<Buffer>((resolve) => {
      const ws = new WebSocket(env!.url, REMOTE_GATEWAY_SUBPROTOCOL.control, {
        perMessageDeflate: false,
      });
      ws.once("message", (data) =>
        resolve(Buffer.isBuffer(data) ? data : Buffer.concat(data as readonly Buffer[])),
      );
    });
    expect(challenge.length).toBe(53);
    expect(challenge.subarray(0, 4).toString("ascii")).toBe("FCDC");
    expect(challenge[4]).toBe(1);
  }, 10_000);

  it("closes control with authentication_failed on a structurally invalid FCDA", async () => {
    env = await startGatewayServer();
    const ws = new WebSocket(env.url, REMOTE_GATEWAY_SUBPROTOCOL.control, {
      perMessageDeflate: false,
    });
    await new Promise<void>((resolve) => ws.once("message", () => resolve()));
    ws.send(Buffer.from([0, 1, 2, 3, 4, 5]));
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  }, 10_000);

  it("closes signal with authentication_failed on a structurally invalid FCSA", async () => {
    env = await startGatewayServer();
    const ws = await connectWs(env.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: "https://app.example.test" },
    });
    ws.send(Buffer.from([0, 1, 2, 3, 4, 5]));
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  });
});

describe("remote_gateway_lazy_import_and_shutdown", () => {
  it("importing the gateway module opens zero Redis sockets", async () => {
    const mod = await import("./gateway");
    expect(typeof mod.RemoteSignalingGateway).toBe("function");
    expect(typeof mod.createRemoteSignalingGateway).toBe("function");
  });

  it("gateway close stops accepting and closes sockets with 1001", async () => {
    env = await startGatewayServer();
    expect(env.gateway.activeSocketCount).toBe(0);
    const ws = await connectWs(env.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: "https://app.example.test" },
    });
    expect(env.gateway.activeSocketCount).toBe(1);
    await env.gateway.close();
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(1001);
  });
});

/**
 * Authenticate a control socket end to end and resolve once auth has fully
 * completed — the gateway reads discovery only after clearing pre-auth state, so
 * a follow-up frame is demuxed as a post-auth frame (not a stray FCDA).
 */
async function connectAuthenticatedControl(target: GatewayTestEnv, ring: TestIdentityRing) {
  const cert = mintDaemonCertificate({
    ring: ring.ring,
    kid: ring.kid,
    ringPrivateKey: ring.privateKey,
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
      }),
    ),
  );
  await authenticated;
  return { ws, queue, cert };
}

const fcrcFrame = (): Uint8Array => {
  const frame = new Uint8Array(98);
  frame.set(new TextEncoder().encode("FCRC"), 0);
  frame[4] = 1;
  return frame;
};

describe("remote_gateway_relay_and_ack", () => {
  it("commits a client FCSE via the store and returns its exact FCAK ack bytes", async () => {
    env = await startGatewayServer();
    const srv = env;
    const admitted = await admitSignalSocket(srv);
    // Client WebRTC offer (admitted -> offered) committed for the admitted child.
    const offer = request(4, 2, 4, 1, admitted.child);
    admitted.ws.send(Buffer.from(offer));
    const received = await admitted.queue.next();

    const page = await srv.store.read(createInput.daemonInstanceId, admitted.child, 0n);
    expect(page.kind).toBe("events");
    if (page.kind === "events") {
      const committed = page.events.find((event) => event.sequence === 4n);
      expect(committed?.request.eventKind).toBe(4);
      // The delivered ACK is byte-identical to the store's committed ackBytes.
      expect(Buffer.from(received)).toEqual(Buffer.from(committed!.ackBytes));
    }
  });

  it("closes 4400 on a frame whose childAttemptId contradicts the binding, with no store mutation", async () => {
    env = await startGatewayServer();
    const srv = env;
    const admitted = await admitSignalSocket(srv);
    const before = await srv.store.read(createInput.daemonInstanceId, admitted.child, 0n);
    const beforeCount = before.kind === "events" ? before.events.length : -1;
    // producerRole 2 (client) but a foreign childAttemptId → binding mismatch.
    admitted.ws.send(Buffer.from(request(4, 2, 4, 1, id(99))));
    const closed = await waitForClose(admitted.ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
    const after = await srv.store.read(createInput.daemonInstanceId, admitted.child, 0n);
    expect(after.kind === "events" && after.events.length).toBe(beforeCount);
  });

  it("closes 4400 on an inbound FCRC frame on a signal socket", async () => {
    env = await startGatewayServer();
    const srv = env;
    const admitted = await admitSignalSocket(srv);
    admitted.ws.send(Buffer.from(fcrcFrame()));
    const closed = await waitForClose(admitted.ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
  });

  it("closes 4400 on an inbound FCRC frame on a control socket", async () => {
    const ring = makeIdentityRing();
    env = await startGatewayServer({ daemonCertificateVerifier: buildRingVerifier(ring.ring) });
    const srv = env;
    const { ws } = await connectAuthenticatedControl(srv, ring);
    ws.send(Buffer.from(fcrcFrame()));
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
  });

  it("delivers peer events to the signal socket in order as exact bytes", async () => {
    env = await startGatewayServer();
    const srv = env;
    const admitted = await admitSignalSocket(srv);
    // Reach 'offered' via a client offer, then commit daemon answer + candidate.
    admitted.ws.send(Buffer.from(request(4, 2, 4, 1, admitted.child)));
    await admitted.queue.next(); // ack for the offer (seq 4)

    const answer = request(5, 3, 5, 1, admitted.child);
    await srv.store.commit(createInput.daemonInstanceId, admitted.child, answer, actor("daemon"));
    expect(Buffer.from(await admitted.queue.next())).toEqual(Buffer.from(answer));

    const candidate = request(6, 3, 6, 1, admitted.child);
    await srv.store.commit(
      createInput.daemonInstanceId,
      admitted.child,
      candidate,
      actor("daemon"),
    );
    expect(Buffer.from(await admitted.queue.next())).toEqual(Buffer.from(candidate));
  });

  it("resumes delivery with no skipped peer event after a reconnect", async () => {
    env = await startGatewayServer();
    const srv = env;
    const admitted = await admitSignalSocket(srv);
    // Advance: client offer (seq 4) then daemon answer (seq 5), delivered to A.
    admitted.ws.send(Buffer.from(request(4, 2, 4, 1, admitted.child)));
    await admitted.queue.next(); // offer ack
    const answer = request(5, 3, 5, 1, admitted.child);
    await srv.store.commit(createInput.daemonInstanceId, admitted.child, answer, actor("daemon"));
    await admitted.queue.next(); // answer delivered to socket A

    // Drop A (releases its lease) and reconnect. The admission ticket is single
    // use — socket A already consumed it — so a real reconnecting client mints a
    // fresh ticket for the same attempt and replays the identical admission proof.
    // The store's ticket auth passes on the fresh ticket, then the idempotency
    // path returns the already-committed admission (no second commit), so the new
    // socket re-reads committed peer events from cursor 0.
    admitted.ws.close();
    await waitForClose(admitted.ws);
    const reconnectTicket = await srv.store.issueClientAdmissionTicket({
      daemonInstanceId: createInput.daemonInstanceId,
      childAttemptId: admitted.child,
      originClass: "browser_same_origin",
      accountId: "acct-1",
      deviceAttachmentId: admitted.deviceAttachmentId,
      deviceGeneration: 5n,
      admissionProofSha256: sha256Bytes(admitted.proofBytes),
    });
    const { ws, queue } = await connectWithQueue(srv.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: CONFIGURED_ORIGIN },
    });
    ws.send(
      Buffer.from(
        encodeFcsaFrame({
          ticketId: reconnectTicket.ticketId,
          ticketSecret: reconnectTicket.secret,
          admissionProof: admitted.proofBytes,
        }),
      ),
    );
    // Re-read from cursor 0: every peer event (server bundle seq1, daemon offer
    // seq2, daemon answer seq5) in order, with the client offer (seq4) skipped.
    expect(Buffer.from(await queue.next())).toEqual(
      Buffer.from(request(1, 1, 1, 1, admitted.child)),
    );
    expect(Buffer.from(await queue.next())).toEqual(
      Buffer.from(request(2, 3, 2, 1, admitted.child)),
    );
    expect(Buffer.from(await queue.next())).toEqual(Buffer.from(answer));
    ws.close();
  });
});

describe("remote_gateway_backpressure", () => {
  it("closes 4429 when the authenticated per-socket frame rate is exhausted", async () => {
    // Lower the signaling burst to one; the FakeClock never advances, so the
    // token bucket never refills and the second authenticated frame is rejected.
    env = await startGatewayServer({ policy: { signaling: { perSecond: 1, burst: 1 } } });
    const srv = env;
    const admitted = await admitSignalSocket(srv);
    // First post-auth frame consumes the single token (valid client offer).
    admitted.ws.send(Buffer.from(request(4, 2, 4, 1, admitted.child)));
    await admitted.queue.next(); // offer ack
    // Second frame finds an empty bucket → 4429.
    admitted.ws.send(Buffer.from(request(6, 2, 6, 1, admitted.child)));
    const closed = await waitForClose(admitted.ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure);
  });

  it("closes 4429 when the outbound queue exceeds the unacked-event ceiling (not the rate limiter)", async () => {
    // Drive the OUTBOUND-QUEUE producer of 4429 (distinct from the inbound rate
    // limiter): committed peer events queued to the socket that outrun the
    // unacked-event ceiling. A batch of peer candidates committed synchronously
    // is delivered in one pump loop whose sends have not yet flushed, so the
    // ceiling is crossed deterministically. (The queued-BYTES threshold is the
    // same `trySend` guard; on loopback the kernel accepts small writes
    // synchronously so `bufferedAmount` only grows at kernel-buffer scale — the
    // store's 2 MiB aggregate cap makes the byte threshold unreachable through
    // valid events, so the count dimension is the deterministic assertion.)
    env = await startGatewayServer({ policy: { backpressure: { maxUnackedEvents: 2 } } });
    const srv = env;
    const admitted = await admitSignalSocket(srv);
    // Reach 'answered' so daemon ICE candidates are valid peer events.
    admitted.ws.send(Buffer.from(request(4, 2, 4, 1, admitted.child)));
    await admitted.queue.next(); // offer ack
    await srv.store.commit(
      createInput.daemonInstanceId,
      admitted.child,
      request(5, 3, 5, 1, admitted.child),
      actor("daemon"),
    );
    await admitted.queue.next(); // daemon answer delivered (queue drained → pending ~0)
    // Commit four daemon candidates in one synchronous batch: the memory store's
    // commit body runs synchronously, so all four are committed before the first
    // wake-triggered delivery loop runs and reads them together.
    const floods = [6, 7, 8, 9].map((event) =>
      srv.store.commit(
        createInput.daemonInstanceId,
        admitted.child,
        request(6, 3, event, 1, admitted.child),
        actor("daemon"),
      ),
    );
    const closed = await waitForClose(admitted.ws);
    await Promise.allSettled(floods);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure);
  });
});

describe("remote_gateway_signal_lease_renewal", () => {
  it("renews the per-attachment lease while the socket stays open", async () => {
    // Fake only the interval timer so the socket's I/O (real) still admits, then
    // assert the renewal timer re-acquires the lease. A gateway that acquired the
    // lease once and never renewed would leave callCount at 1 and let the lease
    // TTL expire out from under a live socket (cap bypass).
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    try {
      env = await startGatewayServer();
      const srv = env;
      const acquire = vi.spyOn(srv.store, "acquireSignalingSocketLease");
      const admitted = await admitSignalSocket(srv);
      expect(acquire).toHaveBeenCalledTimes(1); // acquired at admission
      await vi.advanceTimersByTimeAsync(REMOTE_GATEWAY_SIGNAL_LEASE_RENEWAL_MS + 1);
      expect(acquire.mock.calls.length).toBeGreaterThanOrEqual(2); // renewed while open
      admitted.ws.close();
    } finally {
      vi.useRealTimers();
    }
  });
});
