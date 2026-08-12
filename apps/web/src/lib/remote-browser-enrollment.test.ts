import {
  CustodyClass,
  decodePossessionProof,
  PossessionPurpose,
} from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import {
  beginBrowserRemoteEnrollment,
  type EnrollmentTransport,
} from "./remote-browser-enrollment";
import {
  REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY,
  RemoteBrowserIdentityCustodyError,
  RemoteBrowserIdentityCustodyProvider,
  type RemoteBrowserIdentityStore,
  type RemoteBrowserIdentityStoredRecord,
} from "./remote-browser-identity-custody";

const ORIGIN = "https://app.flycockpit.example";

const SUPPORTED_CAPABILITY = {
  nonExtractableP256: true,
  indexedDb: true,
  supported: true,
} as const;

const POLICY = { minCustodyClass: CustodyClass.origin_protected, allowUserPresenceRequired: false };

function makeFakeStore(): RemoteBrowserIdentityStore & { putShouldFail: boolean } {
  const records = new Map<string, RemoteBrowserIdentityStoredRecord>();
  return {
    putShouldFail: false,
    async open() {
      return { fake: true };
    },
    async get(_db, key) {
      return records.get(key);
    },
    async put(_db, key, value) {
      if (this.putShouldFail) {
        throw new RemoteBrowserIdentityCustodyError("storage_unavailable", "injected put failure");
      }
      records.set(key, value);
    },
    async delete(_db, key) {
      records.delete(key);
    },
    async reserveGeneration(_db) {
      if (this.putShouldFail) {
        throw new RemoteBrowserIdentityCustodyError("storage_unavailable", "injected put failure");
      }
      // Atomic: no await between the read and the write.
      const seq = records.get(REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY);
      const current = seq && "highWater" in seq ? seq.highWater : 0n;
      const next = current + 1n;
      records.set(REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY, { highWater: next });
      return next;
    },
  };
}

function recordingTransport(): EnrollmentTransport<string> & { calls: Uint8Array[] } {
  const calls: Uint8Array[] = [];
  return {
    calls,
    async send(encodedProof) {
      calls.push(encodedProof);
      return "accepted";
    },
  };
}

function baseOptions(
  provider: RemoteBrowserIdentityCustodyProvider,
  transport: EnrollmentTransport<string>,
) {
  return {
    provider,
    transport,
    subjectKind: 1 as const,
    policy: POLICY,
    purpose: PossessionPurpose.enroll_proposed,
    certificateId: new Uint8Array(16).fill(5),
    requestId: new Uint8Array(16).fill(6),
    issuerStatusDigest: new Uint8Array(32).fill(7),
    challenge: new Uint8Array(32).fill(8),
    transcriptDigest: new Uint8Array(32).fill(9),
    issuedAt: 1_000n,
  };
}

describe("begin_browser_remote_enrollment", () => {
  it("capability failure surfaces the typed error with the transport never invoked", async () => {
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store: makeFakeStore(),
      capability: SUPPORTED_CAPABILITY,
    });
    const transport = recordingTransport();
    await expect(
      beginBrowserRemoteEnrollment({
        ...baseOptions(provider, transport),
        capability: { nonExtractableP256: false, indexedDb: false, supported: false },
      }),
    ).rejects.toMatchObject({ code: "unsupported_engine" });
    expect(transport.calls).toHaveLength(0);
  });

  it("custody generation failure surfaces the typed error with the transport never invoked", async () => {
    const store = makeFakeStore();
    store.putShouldFail = true;
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    const transport = recordingTransport();
    await expect(
      beginBrowserRemoteEnrollment({
        ...baseOptions(provider, transport),
        capability: SUPPORTED_CAPABILITY,
      }),
    ).rejects.toMatchObject({ code: "storage_unavailable" });
    expect(transport.calls).toHaveLength(0);
  });

  it("success hands the transport a production codec-encoded possession proof", async () => {
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store: makeFakeStore(),
      capability: SUPPORTED_CAPABILITY,
    });
    const transport = recordingTransport();
    const result = await beginBrowserRemoteEnrollment({
      ...baseOptions(provider, transport),
      capability: SUPPORTED_CAPABILITY,
    });
    expect(transport.calls).toHaveLength(1);
    expect(result.transportResult).toBe("accepted");
    expect(Array.from(result.encodedProof)).toEqual(Array.from(transport.calls[0]!));
    expect(result.encodedProof).toHaveLength(239);

    const proof = decodePossessionProof(transport.calls[0]!);
    expect(proof.purpose).toBe(PossessionPurpose.enroll_proposed);
    expect(proof.subjectKind).toBe(1);
    expect(Array.from(proof.subjectId)).toEqual(Array.from(result.handleId));
    expect(Array.from(proof.certificateId)).toEqual(Array.from(new Uint8Array(16).fill(5)));
    expect(proof.generation).toBe(1n);
    expect(proof.issuedAt).toBe(1_000n);
    expect(proof.expiresAt).toBe(1_060n);
  });
});
