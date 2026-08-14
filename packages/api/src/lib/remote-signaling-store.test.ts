import { createHash } from "node:crypto";
import {
  daemonAdmissionOfferDigest,
  decodeRemoteSignalingEventRequestV1,
  encodeClientAdmissionProofV1,
  encodeDaemonAdmissionOfferV1,
  encodeRemoteChildAuthenticationBundleV1,
  encodeRemoteEndpointFinalProofV1,
  encodeRemoteFallbackNoiseCompleteV1,
  encodeRemoteFallbackPairAuthenticatedV1,
  encodeRemoteSignalingEventRequestV1,
  encodeRemoteSignalingReadyV1,
  encodeRemoteWebRtcAnswerV1,
  encodeRemoteWebRtcCandidateV1,
  encodeRemoteWebRtcIceCompleteV1,
  encodeRemoteWebRtcOfferV1,
  REMOTE_SIGNALING_REQUEST_VECTORS,
  remoteChildAuthenticationDigests,
  remoteFinalProofSetDigest,
} from "@flycockpit/cockpit-protocol";
import { describe, expect, it, vi } from "vitest";
import {
  MemoryRemoteSignalingAttemptStore,
  REMOTE_SIGNALING_ADMISSION_TICKET_TTL_MS,
  REMOTE_SIGNALING_SOCKET_LEASE_TTL_MS,
  RedisRemoteSignalingAttemptStore,
  RemoteSignalingStoreError,
} from "./remote-signaling-store";

vi.mock("@flycockpit/queue/connection", () => ({ createRedisConnection: vi.fn() }));

const id = (start: number) => Uint8Array.from({ length: 16 }, (_, index) => start + index);
const digest = (start: number) => Uint8Array.from({ length: 32 }, (_, index) => start + index);
const signature = () => new Uint8Array(64).fill(9);
const daemonOffer = (childAttemptId = id(1), transport: 1 | 2 = 1) =>
  encodeDaemonAdmissionOfferV1({
    instanceId: id(20),
    daemonDeviceId: id(40),
    daemonDeviceGeneration: 1n,
    daemonCertificateId: id(60),
    daemonCertificateGeneration: 1n,
    logicalAttachmentId: id(80),
    childAttemptId,
    grantJti: id(100),
    grantDigest: digest(1),
    serverNonce: digest(40),
    serviceVersion: 1n,
    policyEpoch: 1n,
    policyDigest: digest(80),
    authorizedTransportBits: transport,
    daemonTupleIds: [1],
    offerJti: id(120),
    issuedAt: 1n,
    expiresAt: 2n,
    signature: signature(),
  });
const fromHex = (value: string) =>
  Uint8Array.from(value.match(/../g)!.map((byte) => Number.parseInt(byte, 16)));
const finalProof = (role: 1 | 2, transport: 1 | 2 = 1, childAttemptId = id(1)) =>
  encodeRemoteEndpointFinalProofV1({
    role,
    transport,
    childAttemptId,
    transportEpoch: id(50),
    admissionSequence: 3n,
    grantDigest: digest(1),
    negotiationDigest: digest(40),
    binding: new Uint8Array(96).fill(8),
    proofJti: id(role === 1 ? 140 : 160),
    certificateId: id(role === 1 ? 180 : 200),
    certificateGeneration: 1n,
    signature: new Uint8Array(64).fill(role),
  });
const request = (
  kind: number,
  role: 1 | 2 | 3,
  event = kind,
  transport: 1 | 2 = kind >= 8 && kind <= 9 ? 2 : 1,
  childAttemptId = id(1),
) => {
  let payload = new Uint8Array();
  const description = {
    childAttemptId,
    transportEpoch: id(50),
    descriptionId: id(70),
    sdp: new TextEncoder().encode("v=0\r\n"),
  };
  if (kind === 1)
    payload = encodeRemoteChildAuthenticationBundleV1({
      childAttemptId,
      grantJws: Uint8Array.of(1),
      clientCertificateJws: Uint8Array.of(2),
      daemonCertificateJws: Uint8Array.of(3),
      authorityStatusJws: Uint8Array.of(4),
      servicePolicyJws: Uint8Array.of(5),
    });
  if (kind === 2) payload = daemonOffer(childAttemptId, transport);
  if (kind === 3)
    payload = encodeClientAdmissionProofV1({
      tenantId: id(20),
      accountId: id(40),
      clientDeviceId: id(60),
      clientDeviceGeneration: 1n,
      clientCertificateId: id(80),
      clientCertificateGeneration: 1n,
      logicalAttachmentId: id(100),
      childAttemptId,
      grantJti: id(120),
      grantDigest: digest(1),
      daemonOfferDigest: daemonAdmissionOfferDigest(daemonOffer(childAttemptId, transport)),
      daemonOfferJti: id(120),
      chosenTransport: transport,
      clientTupleIds: [1],
      daemonTupleIds: [1],
      selectedTupleId: 1,
      policyDigest: digest(80),
      serverNonce: digest(10),
      clientNonce: digest(50),
      issuedAt: 1n,
      expiresAt: 2n,
      proofJti: id(30),
      signature: signature(),
    });
  if (kind === 4) payload = encodeRemoteWebRtcOfferV1(description);
  if (kind === 5) payload = encodeRemoteWebRtcAnswerV1(description);
  if (kind === 6)
    payload = encodeRemoteWebRtcCandidateV1({
      role: role === 2 ? 1 : 2,
      childAttemptId,
      transportEpoch: id(50),
      candidateId: id(event),
      sdpMid: "0",
      sdpMLineIndex: 0,
      candidate: "candidate:1 1 UDP 1 192.0.2.1 9 typ host",
    });
  if (kind === 7)
    payload = encodeRemoteWebRtcIceCompleteV1({
      role: role === 2 ? 1 : 2,
      childAttemptId,
      transportEpoch: id(50),
    });
  if (kind === 8)
    payload = encodeRemoteFallbackPairAuthenticatedV1({
      pairId: id(90),
      pairGeneration: 1n,
      routeGeneration: 1n,
      clientSocketGeneration: 1n,
      daemonSocketGeneration: 1n,
      admissionSequence: 3n,
      pairAuthorizationDigest: digest(90),
    });
  if (kind === 9)
    payload = encodeRemoteFallbackNoiseCompleteV1({
      role: role === 2 ? 1 : 2,
      pairId: id(90),
      socketGeneration: 1n,
      noiseHandshakeHash: digest(10),
      prologueDigest: digest(50),
      connectionNonce: digest(90),
    });
  if (kind === 10 || kind === 11)
    payload = finalProof(kind === 10 ? 1 : 2, transport, childAttemptId);
  if (kind === 12) {
    const client = finalProof(1, transport, childAttemptId),
      daemon = finalProof(2, transport, childAttemptId);
    payload = encodeRemoteSignalingReadyV1({
      verifiedPeerProofJti: id(role === 2 ? 160 : 140),
      finalProofSetDigest: remoteFinalProofSetDigest(client, daemon),
    });
  }
  return encodeRemoteSignalingEventRequestV1({
    transport,
    producerRole: role,
    eventKind: kind as 1,
    childAttemptId,
    eventId: id(32 + event),
    payload,
  });
};
const actor = (role: "server" | "client" | "daemon") => ({
  role,
  actor: `${role}-one`,
  generation: 1n,
});
const createInput = {
  daemonInstanceId: "abcdefghijklmnopqrstuv",
  childAttemptId: id(1),
  transportKind: "webrtc" as const,
  participantRefs: ["opaque-a", "opaque-b"] as const,
};

describe("remote signaling attempt store", () => {
  it("executes shared literal request and ACK vectors", async () => {
    const store = new MemoryRemoteSignalingAttemptStore(
      () => 1_000,
      (out) => out.fill(7),
    );
    const [available, superseded] = REMOTE_SIGNALING_REQUEST_VECTORS;
    expect(
      (await store.create(createInput, fromHex(available!.requestHex), actor("server"))).ackBytes,
    ).toEqual(fromHex(available!.ackHex));
    const committed = await store.commit(
      createInput.daemonInstanceId,
      id(1),
      fromHex(superseded!.requestHex),
      actor("server"),
    );
    expect(committed.ackBytes).toEqual(fromHex(superseded!.ackHex));
  });
  it("remote_signaling_state_machine_matrix", async () => {
    let now = 1_000;
    const store = new MemoryRemoteSignalingAttemptStore(
      () => now,
      (out) => out.fill(7),
    );
    expect((await store.create(createInput, request(1, 1), actor("server"))).sequence).toBe(1n);
    expect(
      (await store.commit(createInput.daemonInstanceId, id(1), request(2, 3), actor("daemon")))
        .sequence,
    ).toBe(2n);
    expect(
      (await store.commit(createInput.daemonInstanceId, id(1), request(3, 2), actor("client")))
        .sequence,
    ).toBe(3n);
    expect(
      (await store.commit(createInput.daemonInstanceId, id(1), request(4, 2), actor("client")))
        .sequence,
    ).toBe(4n);
    expect(
      (await store.commit(createInput.daemonInstanceId, id(1), request(5, 3), actor("daemon")))
        .sequence,
    ).toBe(5n);
    await store.commit(createInput.daemonInstanceId, id(1), request(6, 2, 20), actor("client"));
    await store.commit(createInput.daemonInstanceId, id(1), request(6, 3, 21), actor("daemon"));
    await store.commit(createInput.daemonInstanceId, id(1), request(7, 2, 22), actor("client"));
    await store.commit(createInput.daemonInstanceId, id(1), request(7, 3, 23), actor("daemon"));
    await store.commit(createInput.daemonInstanceId, id(1), request(10, 2, 24), actor("client"));
    await store.commit(createInput.daemonInstanceId, id(1), request(11, 3, 25), actor("daemon"));
    await store.commit(createInput.daemonInstanceId, id(1), request(12, 2, 26), actor("client"));
    expect(
      (await store.commit(createInput.daemonInstanceId, id(1), request(12, 3, 27), actor("daemon")))
        .sequence,
    ).toBe(13n);
    const fallbackInput = {
        ...createInput,
        childAttemptId: id(2),
        transportKind: "websocket_data" as const,
      },
      fallbackStore = new MemoryRemoteSignalingAttemptStore(
        () => 1_000,
        (out) => out.fill(8),
      );
    // Use the same dependency-owned child ID throughout a second transport matrix.
    const fallbackBytes = (kind: number, role: 1 | 2 | 3, event: number) =>
      request(kind, role, event, 2, id(2));
    await fallbackStore.create(fallbackInput, fallbackBytes(1, 1, 40), actor("server"));
    await fallbackStore.commit(
      createInput.daemonInstanceId,
      id(2),
      fallbackBytes(2, 3, 41),
      actor("daemon"),
    );
    await fallbackStore.commit(
      createInput.daemonInstanceId,
      id(2),
      fallbackBytes(3, 2, 42),
      actor("client"),
    );
    await fallbackStore.commit(
      createInput.daemonInstanceId,
      id(2),
      fallbackBytes(8, 1, 43),
      actor("server"),
    );
    await fallbackStore.commit(
      createInput.daemonInstanceId,
      id(2),
      fallbackBytes(9, 2, 44),
      actor("client"),
    );
    await fallbackStore.commit(
      createInput.daemonInstanceId,
      id(2),
      fallbackBytes(9, 3, 45),
      actor("daemon"),
    );
    await fallbackStore.commit(
      createInput.daemonInstanceId,
      id(2),
      fallbackBytes(10, 2, 46),
      actor("client"),
    );
    await fallbackStore.commit(
      createInput.daemonInstanceId,
      id(2),
      fallbackBytes(11, 3, 47),
      actor("daemon"),
    );
    await fallbackStore.commit(
      createInput.daemonInstanceId,
      id(2),
      fallbackBytes(12, 2, 48),
      actor("client"),
    );
    expect(
      (
        await fallbackStore.commit(
          createInput.daemonInstanceId,
          id(2),
          fallbackBytes(12, 3, 49),
          actor("daemon"),
        )
      ).sequence,
    ).toBe(10n);
    now = 301_000;
    expect((await store.read(createInput.daemonInstanceId, id(1), 0n)).kind).toBe("unavailable");
  });
  it("remote_signaling_duplicate_event_is_idempotent", async () => {
    const store = new MemoryRemoteSignalingAttemptStore(
      () => 1_000,
      (out) => out.fill(7),
    );
    const bytes = request(1, 1);
    await store.create(createInput, bytes, actor("server"));
    const replay = await store.create(createInput, bytes, actor("server"));
    expect(replay.kind).toBe("replay");
    await expect(
      store.create(createInput, bytes, { ...actor("server"), generation: 2n }),
    ).rejects.toBeInstanceOf(RemoteSignalingStoreError);
  });
  it("remote_signaling_cursor_replay_survives_missed_pubsub", async () => {
    const store = new MemoryRemoteSignalingAttemptStore(
      () => 1_000,
      (out) => out.fill(7),
    );
    const available = request(1, 1),
      bundle = decodeRemoteSignalingEventRequestV1(available).payload,
      input = {
        ...createInput,
        discovery: {
          daemonCertificateGeneration: 4n,
          discoveryId: id(90),
          authBundleDigest: remoteChildAuthenticationDigests(bundle).authBundleDigest,
        },
      };
    const lease = await store.authenticateInstanceWake(createInput.daemonInstanceId, 4n, 10n, 0n);
    await store.create(input, available, actor("server"));
    const discovery = await store.readDiscovery(createInput.daemonInstanceId, 4n, 10n, 0n);
    expect(discovery.kind).toBe("entries");
    if (discovery.kind === "entries") {
      expect(discovery.entries).toHaveLength(1);
      expect(discovery.entries[0]?.childAttemptId).toEqual(id(1));
    }
    await store.ackDiscovery(createInput.daemonInstanceId, 4n, 10n, 0n, 1n);
    await store.closeInstanceWake(createInput.daemonInstanceId, 4n, lease);
    await store.commit(createInput.daemonInstanceId, id(1), request(2, 3), actor("daemon"));
    const page = await store.read(createInput.daemonInstanceId, id(1), 0n);
    expect(page.kind).toBe("events");
    if (page.kind === "events")
      expect(page.events.map((event) => event.sequence)).toEqual([1n, 2n]);
  });
  it("remote_signaling_absolute_ttl_never_refreshes", async () => {
    let now = 4_000;
    const store = new MemoryRemoteSignalingAttemptStore(
      () => now,
      (out) => out.fill(7),
    );
    await store.create(createInput, request(1, 1), actor("server"));
    const metadata = await store.metadata(createInput.daemonInstanceId, id(1));
    expect("expiresAtMs" in metadata && metadata.expiresAtMs).toBe(304_000);
    now = 304_000;
    await expect(
      store.commit(createInput.daemonInstanceId, id(1), request(2, 3), actor("daemon")),
    ).rejects.toMatchObject({ code: "unavailable" });
    expect(await store.metadata(createInput.daemonInstanceId, id(1))).toEqual({
      kind: "unavailable",
    });
  });
  it("remote_signaling_limits_are_atomic", async () => {
    const store = new MemoryRemoteSignalingAttemptStore(
      () => 1_000,
      (out) => out.fill(7),
    );
    await store.create(createInput, request(1, 1), actor("server"));
    await store.commit(createInput.daemonInstanceId, id(1), request(2, 3), actor("daemon"));
    await store.commit(createInput.daemonInstanceId, id(1), request(3, 2), actor("client"));
    await store.commit(createInput.daemonInstanceId, id(1), request(4, 2), actor("client"));
    for (let index = 0; index < 64; index++)
      await store.commit(
        createInput.daemonInstanceId,
        id(1),
        request(6, 2, 80 + index),
        actor("client"),
      );
    await expect(
      store.commit(createInput.daemonInstanceId, id(1), request(6, 2, 200), actor("client")),
    ).rejects.toMatchObject({ code: "invalid_transition" });
    const page = await store.read(createInput.daemonInstanceId, id(1), 0n);
    expect(page.kind === "events" && page.latestSequence).toBe(68n);
  });
  it("remote_signaling_wake_route_privacy", async () => {
    const wakeups: Array<{ route: Uint8Array; sequence: bigint }> = [];
    const store = new MemoryRemoteSignalingAttemptStore(
      () => 1_000,
      (out) => out.fill(19),
      (route, sequence) => wakeups.push({ route, sequence }),
    );
    await store.create(createInput, request(1, 1), actor("server"));
    const metadata = await store.metadata(createInput.daemonInstanceId, id(1));
    const route = new Uint8Array(16).fill(19);
    expect("attemptWakeRouteId" in metadata && metadata.attemptWakeRouteId).toEqual(route);
    expect(wakeups).toEqual([{ route, sequence: 1n }]);
    expect(Array.from(wakeups[0]!.route)).toHaveLength(16);
    expect(wakeups[0]!.sequence).toBe(1n);
  });
  it("remote_signaling_indeterminate_retry", async () => {
    const store = new MemoryRemoteSignalingAttemptStore(
      () => 1_000,
      (out) => out.fill(7),
    );
    const bytes = request(1, 1),
      first = await store.create(createInput, bytes, actor("server"));
    const recovered = await store.create(createInput, bytes, actor("server"));
    expect(recovered).toEqual({ ...first, kind: "replay" });
  });
  it("remote_signaling_redis_outage_has_no_memory_fallback", async () => {
    const redis = { eval: vi.fn().mockRejectedValue(new Error("redis unavailable")) },
      store = new RedisRemoteSignalingAttemptStore(redis as never, (out) => out.fill(7));
    await expect(store.create(createInput, request(1, 1), actor("server"))).rejects.toThrow(
      "redis unavailable",
    );
    expect(redis.eval).toHaveBeenCalledTimes(1);
  });
});

describe("remote_signaling_socket_lease_cap", () => {
  const leaseError = async (promise: Promise<unknown>) => {
    const error = await promise.then(
      () => undefined,
      (reason: unknown) => reason,
    );
    return error;
  };

  it("admits two live signal sockets per attachment and conflicts on the third", async () => {
    const store = new MemoryRemoteSignalingAttemptStore(
      () => 1_000,
      (out) => out.fill(7),
    );
    await store.acquireSignalingSocketLease("attach-A", "socket-1");
    await store.acquireSignalingSocketLease("attach-A", "socket-2");
    const error = await leaseError(store.acquireSignalingSocketLease("attach-A", "socket-3"));
    expect(error).toBeInstanceOf(RemoteSignalingStoreError);
    expect((error as RemoteSignalingStoreError).code).toBe("conflict");
    // Re-acquiring a held lease refreshes it — it is not a third slot.
    await store.acquireSignalingSocketLease("attach-A", "socket-1");
    // A different attachment has its own independent budget.
    await store.acquireSignalingSocketLease("attach-B", "socket-1");
    await store.acquireSignalingSocketLease("attach-B", "socket-2");
  });

  it("frees a slot on release", async () => {
    const store = new MemoryRemoteSignalingAttemptStore(
      () => 1_000,
      (out) => out.fill(7),
    );
    await store.acquireSignalingSocketLease("attach-A", "socket-1");
    await store.acquireSignalingSocketLease("attach-A", "socket-2");
    expect(
      (
        (await leaseError(
          store.acquireSignalingSocketLease("attach-A", "socket-3"),
        )) as RemoteSignalingStoreError
      ).code,
    ).toBe("conflict");
    await store.releaseSignalingSocketLease("attach-A", "socket-1");
    // The freed slot now admits a new socket.
    await store.acquireSignalingSocketLease("attach-A", "socket-3");
  });

  it("frees a slot when a lease TTL expires under the injected clock", async () => {
    let now = 1_000;
    const store = new MemoryRemoteSignalingAttemptStore(
      () => now,
      (out) => out.fill(7),
    );
    await store.acquireSignalingSocketLease("attach-A", "socket-1");
    await store.acquireSignalingSocketLease("attach-A", "socket-2");
    expect(
      (
        (await leaseError(
          store.acquireSignalingSocketLease("attach-A", "socket-3"),
        )) as RemoteSignalingStoreError
      ).code,
    ).toBe("conflict");
    now += REMOTE_SIGNALING_SOCKET_LEASE_TTL_MS + 1; // both leases expire
    // The expired leases free their slots.
    await store.acquireSignalingSocketLease("attach-A", "socket-3");
    await store.acquireSignalingSocketLease("attach-A", "socket-4");
  });

  it("a renewed lease keeps holding its slot past the original TTL", async () => {
    let now = 1_000;
    const store = new MemoryRemoteSignalingAttemptStore(
      () => now,
      (out) => out.fill(7),
    );
    await store.acquireSignalingSocketLease("attach-A", "socket-1");
    await store.acquireSignalingSocketLease("attach-A", "socket-2");
    // Just before expiry, both live sockets renew (what the gateway's renewal
    // timer does for the connection's whole lifetime).
    now += REMOTE_SIGNALING_SOCKET_LEASE_TTL_MS - 1;
    await store.acquireSignalingSocketLease("attach-A", "socket-1");
    await store.acquireSignalingSocketLease("attach-A", "socket-2");
    // Past the ORIGINAL TTL the renewed leases still occupy both slots, so a
    // third live socket is refused — the cap holds for the connection lifetime,
    // not just the first TTL window.
    now += 2;
    const error = await leaseError(store.acquireSignalingSocketLease("attach-A", "socket-3"));
    expect((error as RemoteSignalingStoreError).code).toBe("conflict");
  });
});

describe("remote_signaling_admission_tickets", () => {
  const sha256 = (bytes: Uint8Array) => createHash("sha256").update(Buffer.from(bytes)).digest();
  const sha256Hex = (bytes: Uint8Array) =>
    createHash("sha256").update(Buffer.from(bytes)).digest("hex");
  // The kind-3 client_admission_proof FCSE and the exact ClientAdmissionProofV1
  // payload the client commits (matches the daemon offer committed below).
  const proofRequest = () => request(3, 2);
  const proofPayload = () => decodeRemoteSignalingEventRequestV1(proofRequest()).payload;
  // A VALID kind-3 admission proof whose payload differs from the standard
  // `proofPayload()` only in its `chosenTransport` (2 vs 1) — self-consistent
  // with the envelope transport (so it passes the pre-auth structural checks) and
  // bound to the same child id(1), but its digest does NOT match a ticket minted
  // for the default proof. Presenting it (correct secret/origin) fails ONLY the
  // proof-of-possession digest check, proving a wrong proof is rejected without
  // consuming the ticket.
  const wrongProofRequest = () => request(3, 2, 3, 2);

  async function daemonOfferedAttempt(now: () => number) {
    const store = new MemoryRemoteSignalingAttemptStore(now, (out) => out.fill(7));
    await store.create(createInput, request(1, 1), actor("server"));
    await store.commit(createInput.daemonInstanceId, id(1), request(2, 3), actor("daemon"));
    return store;
  }
  const mint = (
    store: MemoryRemoteSignalingAttemptStore,
    overrides?: Partial<{ childAttemptId: Uint8Array; admissionProofSha256: Uint8Array }>,
  ) =>
    store.issueClientAdmissionTicket({
      daemonInstanceId: createInput.daemonInstanceId,
      childAttemptId: overrides?.childAttemptId ?? id(1),
      originClass: "browser_same_origin",
      accountId: "acct-1",
      deviceAttachmentId: "attach-1",
      deviceGeneration: 5n,
      admissionProofSha256: overrides?.admissionProofSha256 ?? sha256(proofPayload()),
    });

  const admissionError = async (promise: Promise<unknown>) =>
    promise.then(
      () => undefined,
      (reason: unknown) => reason as RemoteSignalingStoreError,
    );

  it("admits with a matching ticket, derives the actor from the ticket, and consumes it", async () => {
    const store = await daemonOfferedAttempt(() => 1_000);
    const { ticketId, secret } = await mint(store);
    const result = await store.commitClientAdmission(
      createInput.daemonInstanceId,
      id(1),
      proofRequest(),
      {
        ticketId,
        secretSha256Hex: sha256Hex(secret),
        originClass: "browser_same_origin",
      },
    );
    expect(result.result.kind).toBe("committed");
    // Actor is server-derived from the ticket, not from the client-declared proof bytes.
    expect(result.actor).toEqual({ role: "client", actor: "attach-1", generation: 5n });
    expect(result.deviceAttachmentId).toBe("attach-1");

    // The ticket is consumed: a replay of the exact same authenticated FCSE now
    // fails closed (the ticket is gone), rather than returning a second admission.
    const replay = await admissionError(
      store.commitClientAdmission(createInput.daemonInstanceId, id(1), proofRequest(), {
        ticketId,
        secretSha256Hex: sha256Hex(secret),
        originClass: "browser_same_origin",
      }),
    );
    expect(replay?.code).toBe("auth_failed");
  });

  it("rejects a replayed proof presented with a wrong secret after consumption (no second admission)", async () => {
    const store = await daemonOfferedAttempt(() => 1_000);
    const { ticketId, secret } = await mint(store);
    // First socket admits with the correct secret.
    const first = await store.commitClientAdmission(
      createInput.daemonInstanceId,
      id(1),
      proofRequest(),
      {
        ticketId,
        secretSha256Hex: sha256Hex(secret),
        originClass: "browser_same_origin",
      },
    );
    expect(first.result.kind).toBe("committed");
    // A second socket replays the identical proof/event id with a WRONG secret.
    // The old bug returned `replay` (ticket check ran after the idempotency
    // short-circuit); it must now fail closed with no second admission.
    const replay = await admissionError(
      store.commitClientAdmission(createInput.daemonInstanceId, id(1), proofRequest(), {
        ticketId,
        secretSha256Hex: sha256Hex(new Uint8Array(32).fill(9)),
        originClass: "browser_same_origin",
      }),
    );
    expect(replay?.code).toBe("auth_failed");
  });

  it("rejects the same ticket on a second distinct admission (single use)", async () => {
    const store = await daemonOfferedAttempt(() => 1_000);
    const { ticketId, secret } = await mint(store);
    await store.commitClientAdmission(createInput.daemonInstanceId, id(1), proofRequest(), {
      ticketId,
      secretSha256Hex: sha256Hex(secret),
      originClass: "browser_same_origin",
    });
    // A concurrent second connection with a fresh (unseen) event id cannot reuse
    // the consumed ticket: the idempotency short-circuit does not apply and the
    // ticket is gone -> auth_failed.
    const fresh = encodeRemoteSignalingEventRequestV1({
      transport: 1,
      producerRole: 2,
      eventKind: 3,
      childAttemptId: id(1),
      eventId: id(250),
      payload: proofPayload(),
    });
    const error = await admissionError(
      store.commitClientAdmission(createInput.daemonInstanceId, id(1), fresh, {
        ticketId,
        secretSha256Hex: sha256Hex(secret),
        originClass: "browser_same_origin",
      }),
    );
    expect(error?.code).toBe("auth_failed");
  });

  it("rejects a wrong secret, origin class, child, and proof digest without consuming the ticket", async () => {
    for (const bad of [
      {
        label: "secret",
        ticketOverride: undefined,
        proof: proofRequest(),
        secretSha256Hex: sha256Hex(new Uint8Array(32).fill(1)),
        originClass: "browser_same_origin",
        child: id(1),
      },
      {
        label: "origin",
        ticketOverride: undefined,
        proof: proofRequest(),
        secretSha256Hex: undefined,
        originClass: "native_no_origin",
        child: id(1),
      },
      {
        label: "proofDigest",
        ticketOverride: undefined,
        proof: wrongProofRequest(),
        secretSha256Hex: undefined,
        originClass: "browser_same_origin",
        child: id(1),
      },
    ] as const) {
      const store = await daemonOfferedAttempt(() => 1_000);
      const { ticketId, secret } = await mint(store, bad.ticketOverride);
      const error = await admissionError(
        store.commitClientAdmission(createInput.daemonInstanceId, bad.child, bad.proof, {
          ticketId,
          secretSha256Hex: bad.secretSha256Hex ?? sha256Hex(secret),
          originClass: bad.originClass,
        }),
      );
      expect(error?.code, bad.label).toBe("auth_failed");
      // The ticket survives the failure: a correct commit still admits.
      const ok = await store.commitClientAdmission(
        createInput.daemonInstanceId,
        id(1),
        proofRequest(),
        {
          ticketId,
          secretSha256Hex: sha256Hex(secret),
          originClass: "browser_same_origin",
        },
      );
      expect(ok.result.kind, bad.label).toBe("committed");
    }
  });

  it("rejects a ticket bound to a different child attempt", async () => {
    const store = await daemonOfferedAttempt(() => 1_000);
    // The ticket is bound to child id(2); the admission targets child id(1).
    const { ticketId, secret } = await mint(store, { childAttemptId: id(2) });
    const error = await admissionError(
      store.commitClientAdmission(createInput.daemonInstanceId, id(1), proofRequest(), {
        ticketId,
        secretSha256Hex: sha256Hex(secret),
        originClass: "browser_same_origin",
      }),
    );
    expect(error?.code).toBe("auth_failed");
  });

  it("rejects an expired ticket after 30 seconds", async () => {
    let now = 1_000;
    const store = await daemonOfferedAttempt(() => now);
    const { ticketId, secret } = await mint(store);
    now += REMOTE_SIGNALING_ADMISSION_TICKET_TTL_MS + 1;
    const error = await admissionError(
      store.commitClientAdmission(createInput.daemonInstanceId, id(1), proofRequest(), {
        ticketId,
        secretSha256Hex: sha256Hex(secret),
        originClass: "browser_same_origin",
      }),
    );
    expect(error?.code).toBe("auth_failed");
  });
});
