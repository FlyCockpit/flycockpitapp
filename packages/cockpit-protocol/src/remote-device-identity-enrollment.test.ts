import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  buildEnrollmentDiscoveryLink,
  CERTIFICATE_LIFECYCLE_ACTIONS,
  CERTIFICATE_OPERATION_STATES,
  CERTIFICATE_OPERATION_TERMINAL_REASONS,
  deriveSasV1,
  ENROLLMENT_PARTICIPANT_ROLES,
  ENROLLMENT_STATES,
  ENROLLMENT_TERMINAL_REASONS,
  EnrollmentProtocolError,
  formatEnrollmentDeepLink,
  formatEnrollmentHttpsUrl,
  parseEnrollmentDeepLink,
  parseEnrollmentHttpsUrl,
  parseRemoteEnrollmentCreateResultV1,
  parseRemoteEnrollmentErrorEnvelopeV1,
  parseRemoteEnrollmentMutationResultV1,
  parseRemoteEnrollmentProgressV1,
  REMOTE_DEVICE_LIFECYCLE,
  REVOCATION_ACTOR_MODES,
  REVOCATION_STATES,
  REVOCATION_TERMINAL_REASONS,
  SAS_V1_BLOCK_COUNT,
  SAS_V1_OKM_LEN,
  SAS_V1_REJECT_THRESHOLD,
  SAS_V1_SALT_DIGEST,
  sasV1InfoPreimage,
  sasV1Okm,
  sasV1SaltPreimage,
  validateCertificateOperationStateTerminalReasonPair,
  validateEnrollmentStateTerminalReasonPair,
  validateRevocationStateTerminalReasonPair,
  validateSasPreimage,
} from "./remote-device-identity-enrollment";
import { remoteIdentitySha256Sync } from "./remote-identity-protocol";

const here = dirname(fileURLToPath(import.meta.url));

interface SasFixtureVector {
  name: string;
  transcriptDigestHex: string;
  acceptedIndex: number;
  acceptedBlockHex: string;
  acceptedBlockInteger: number;
  sas: string;
  digits: string;
  rejectedBlocks?: { index: number; blockHex: string; blockInteger: number }[];
}
interface SasFixture {
  schemaVersion: number;
  saltPreimageHex: string;
  saltDigestHex: string;
  infoPreimageHex: string;
  forbiddenEscapeHex: string;
  okmLen: number;
  blockCount: number;
  rejectThreshold: number;
  modulus: number;
  vectors: SasFixtureVector[];
}

const fixture: SasFixture = JSON.parse(
  readFileSync(join(here, "..", "fixtures", "remote-device-enrollment-sas-v1.json"), "utf8"),
);

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const blockValue = (block: Uint8Array): number => {
  let value = 0;
  for (const byte of block) value = value * 256 + byte;
  return value;
};

describe("remote_enrollment_sas_v1_vectors", () => {
  it("matches the committed salt/info preimages and salt digest", () => {
    expect(fixture.schemaVersion).toBe(1);
    expect(toHex(sasV1SaltPreimage())).toBe(fixture.saltPreimageHex);
    expect(toHex(sasV1InfoPreimage())).toBe(fixture.infoPreimageHex);
    expect(toHex(remoteIdentitySha256Sync(sasV1SaltPreimage()))).toBe(fixture.saltDigestHex);
    expect(toHex(SAS_V1_SALT_DIGEST)).toBe(fixture.saltDigestHex);
  });

  it("rejects the forbidden 5c30 escape in either preimage", () => {
    for (const preimage of [sasV1SaltPreimage(), sasV1InfoPreimage()]) {
      const nulPos = preimage.indexOf(0x00);
      expect(nulPos).toBeGreaterThanOrEqual(0);
      const bad = Uint8Array.from([
        ...preimage.subarray(0, nulPos),
        0x5c,
        0x30,
        ...preimage.subarray(nulPos + 1),
      ]);
      expect(() => validateSasPreimage(bad)).toThrow(EnrollmentProtocolError);
    }
    // Canonical preimages validate.
    expect(() => validateSasPreimage(sasV1SaltPreimage())).not.toThrow();
    expect(() => validateSasPreimage(sasV1InfoPreimage())).not.toThrow();
  });

  it("produces an OKM of exactly 8160 bytes / 1632 blocks", () => {
    const okm = sasV1Okm(new Uint8Array(32));
    expect(okm.length).toBe(SAS_V1_OKM_LEN);
    expect(okm.length).toBe(fixture.okmLen);
    expect(okm.length / 5).toBe(SAS_V1_BLOCK_COUNT);
    expect(SAS_V1_BLOCK_COUNT).toBe(fixture.blockCount);
    expect(SAS_V1_REJECT_THRESHOLD).toBe(fixture.rejectThreshold);
  });

  it("derives every committed vector exactly", () => {
    expect(fixture.vectors.length).toBeGreaterThan(0);
    for (const vector of fixture.vectors) {
      const digest = fromHex(vector.transcriptDigestHex);
      const okm = sasV1Okm(digest);

      // Every explicitly rejected block matches and is >= threshold.
      for (const rejected of vector.rejectedBlocks ?? []) {
        const block = okm.subarray(rejected.index * 5, rejected.index * 5 + 5);
        expect(toHex(block)).toBe(rejected.blockHex);
        const value = blockValue(block);
        expect(value).toBe(rejected.blockInteger);
        expect(value).toBeGreaterThanOrEqual(fixture.rejectThreshold);
      }

      const sas = deriveSasV1(digest);
      expect(sas.acceptedIndex).toBe(vector.acceptedIndex);
      expect(sas.acceptedBlock).toBe(vector.acceptedBlockInteger);
      const acceptedBlock = okm.subarray(vector.acceptedIndex * 5, vector.acceptedIndex * 5 + 5);
      expect(toHex(acceptedBlock)).toBe(vector.acceptedBlockHex);
      expect(blockValue(acceptedBlock)).toBeLessThan(fixture.rejectThreshold);
      expect(sas.digits).toBe(vector.digits);
      expect(sas.display).toBe(vector.sas);
    }
  });

  it("rejects block 0 and accepts block 1 for the rejection vector", () => {
    const vector = fixture.vectors.find((v) => v.name === "rejection_vector");
    expect(vector).toBeDefined();
    if (!vector) return;
    const okm = sasV1Okm(fromHex(vector.transcriptDigestHex));
    expect(blockValue(okm.subarray(0, 5))).toBeGreaterThanOrEqual(fixture.rejectThreshold);
    expect(blockValue(okm.subarray(5, 10))).toBeLessThan(fixture.rejectThreshold);
    expect(deriveSasV1(fromHex(vector.transcriptDigestHex)).acceptedIndex).toBe(1);
  });

  it("is deterministic", () => {
    const zero = new Uint8Array(32);
    expect(deriveSasV1(zero)).toEqual(deriveSasV1(zero));
  });
});

describe("remote_enrollment_link_contract", () => {
  const origin = "https://enroll.flycockpit.example";
  const enrollmentId = new Uint8Array(16).fill(0x11);
  const capability = new Uint8Array(32).fill(0x22);
  const expectedId = "EREREREREREREREREREREQ";
  const expectedCap = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI";

  it("formats the exact HTTPS and deep-link bytes and round-trips", () => {
    const link = buildEnrollmentDiscoveryLink(origin, enrollmentId, capability);
    const url = formatEnrollmentHttpsUrl(link);
    expect(url).toBe(
      `https://enroll.flycockpit.example/remote/enroll?v=1&id=${expectedId}&cap=${expectedCap}`,
    );
    const deep = formatEnrollmentDeepLink(link);
    expect(deep).toBe(`flycockpit://remote/enroll?v=1&id=${expectedId}&cap=${expectedCap}`);

    const parsed = parseEnrollmentHttpsUrl(url);
    expect(parsed.publicOrigin).toBe(origin);
    expect(toHex(parsed.enrollmentId)).toBe(toHex(enrollmentId));
    expect(toHex(parsed.discoveryCapability)).toBe(toHex(capability));

    const parsedDeep = parseEnrollmentDeepLink(deep);
    expect(parsedDeep.publicOrigin).toBe("");
    expect(toHex(parsedDeep.enrollmentId)).toBe(toHex(enrollmentId));
    expect(toHex(parsedDeep.discoveryCapability)).toBe(toHex(capability));
  });

  it("rejects malformed/extra/padded/reordered/fragment variants", () => {
    const url = formatEnrollmentHttpsUrl(
      buildEnrollmentDiscoveryLink(origin, enrollmentId, capability),
    );
    expect(() => parseEnrollmentHttpsUrl(`${url}&extra=1`)).toThrow(EnrollmentProtocolError);
    expect(() => parseEnrollmentHttpsUrl(url.replace("v=1", "v=2"))).toThrow();
    expect(() =>
      parseEnrollmentHttpsUrl(url.replace("/remote/enroll", "/Remote/Enroll")),
    ).toThrow();
    expect(() => parseEnrollmentHttpsUrl(url.replace("https://", "http://"))).toThrow();
    expect(() => parseEnrollmentHttpsUrl(`${url}#frag`)).toThrow();
    // Padded base64url rejected.
    const padded = `https://enroll.flycockpit.example/remote/enroll?v=1&id=${expectedId}=&cap=${expectedCap}`;
    expect(() => parseEnrollmentHttpsUrl(padded)).toThrow();
    // Reordered query rejected.
    const swapped = `https://enroll.flycockpit.example/remote/enroll?v=1&cap=${expectedCap}&id=${expectedId}`;
    expect(() => parseEnrollmentHttpsUrl(swapped)).toThrow();
    // Deep-link fragment rejected.
    const deep = formatEnrollmentDeepLink(
      buildEnrollmentDiscoveryLink(origin, enrollmentId, capability),
    );
    expect(() => parseEnrollmentDeepLink(`${deep}#frag`)).toThrow();
  });

  it("rejects noncanonical origins and zero ids at build time", () => {
    expect(() =>
      buildEnrollmentDiscoveryLink("https://Enroll.flycockpit.example", enrollmentId, capability),
    ).toThrow();
    expect(() =>
      buildEnrollmentDiscoveryLink(
        "https://enroll.flycockpit.example:443",
        enrollmentId,
        capability,
      ),
    ).toThrow();
    expect(() =>
      buildEnrollmentDiscoveryLink("http://enroll.flycockpit.example", enrollmentId, capability),
    ).toThrow();
    expect(() =>
      buildEnrollmentDiscoveryLink("https://enroll.flycockpit.example/", enrollmentId, capability),
    ).toThrow();
    expect(() => buildEnrollmentDiscoveryLink(origin, new Uint8Array(16), capability)).toThrow();
    expect(() => buildEnrollmentDiscoveryLink(origin, enrollmentId, new Uint8Array(32))).toThrow();
  });
});

describe("remote_enrollment_state_reason_matrix", () => {
  it("has the same catalog cardinality as Rust", () => {
    expect(ENROLLMENT_STATES.length).toBe(12);
    expect(ENROLLMENT_TERMINAL_REASONS.length).toBe(7);
    expect(ENROLLMENT_PARTICIPANT_ROLES.length).toBe(3);
    expect(CERTIFICATE_LIFECYCLE_ACTIONS.length).toBe(3);
    expect(CERTIFICATE_OPERATION_STATES.length).toBe(7);
    expect(CERTIFICATE_OPERATION_TERMINAL_REASONS.length).toBe(7);
    expect(REVOCATION_STATES.length).toBe(8);
    expect(REVOCATION_TERMINAL_REASONS.length).toBe(7);
    expect(REVOCATION_ACTOR_MODES.length).toBe(4);
    expect(REMOTE_DEVICE_LIFECYCLE.length).toBe(7);
    expect([...CERTIFICATE_LIFECYCLE_ACTIONS]).toEqual(["enroll", "renew", "rotate"]);
  });

  it("accepts legal pairs and rejects illegal pairs", () => {
    expect(() =>
      validateEnrollmentStateTerminalReasonPair("rejected", "explicit_reject"),
    ).not.toThrow();
    expect(() => validateEnrollmentStateTerminalReasonPair("expired", "expired")).not.toThrow();
    expect(() => validateEnrollmentStateTerminalReasonPair("cancelled", "cancelled")).not.toThrow();
    expect(() =>
      validateEnrollmentStateTerminalReasonPair("superseded", "superseded"),
    ).not.toThrow();
    expect(() => validateEnrollmentStateTerminalReasonPair("rejected", "expired")).toThrow();
    expect(() => validateEnrollmentStateTerminalReasonPair("cancelled", "superseded")).toThrow();

    expect(() =>
      validateCertificateOperationStateTerminalReasonPair("denied", "signer_unavailable"),
    ).not.toThrow();
    expect(() =>
      validateCertificateOperationStateTerminalReasonPair("expired", "cancelled"),
    ).toThrow();

    expect(() =>
      validateRevocationStateTerminalReasonPair("denied", "invalid_approval"),
    ).not.toThrow();
    expect(() => validateRevocationStateTerminalReasonPair("revoked", "invalid_current")).toThrow();
  });
});

describe("remote_enrollment_strict_projection_parse", () => {
  const validId = "EREREREREREREREREREREQ";
  const nonTerminalProgress = {
    schemaVersion: 1,
    enrollmentRequestId: validId,
    enrollmentId: validId,
    deviceId: validId,
    certificateId: validId,
    generation: "1",
    state: "reserved",
    participantRole: "proposed_subject",
    expiresAt: "1699999999",
    proposal: null,
    transcript: null,
    issuerStatus: null,
    authorizationRequestDigest: null,
    certificate: null,
    terminalReason: null,
  };

  it("accepts a valid non-terminal progress projection", () => {
    const parsed = parseRemoteEnrollmentProgressV1(nonTerminalProgress);
    expect(parsed.state).toBe("reserved");
    expect(parsed.terminalReason).toBeNull();
  });

  it("accepts a legal terminal projection", () => {
    const parsed = parseRemoteEnrollmentProgressV1({
      ...nonTerminalProgress,
      state: "cancelled",
      terminalReason: "cancelled",
    });
    expect(parsed.terminalReason).toBe("cancelled");
  });

  it("rejects an unknown extra member", () => {
    expect(() =>
      parseRemoteEnrollmentProgressV1({ ...nonTerminalProgress, extra: "nope" }),
    ).toThrow();
  });

  it("rejects illegal nullability pairs", () => {
    // Non-terminal state with a non-null terminalReason.
    expect(() =>
      parseRemoteEnrollmentProgressV1({ ...nonTerminalProgress, terminalReason: "cancelled" }),
    ).toThrow();
    // Terminal state missing a terminalReason.
    expect(() =>
      parseRemoteEnrollmentProgressV1({ ...nonTerminalProgress, state: "cancelled" }),
    ).toThrow();
    // Illegal terminal state/reason pair.
    expect(() =>
      parseRemoteEnrollmentProgressV1({
        ...nonTerminalProgress,
        state: "cancelled",
        terminalReason: "expired",
      }),
    ).toThrow();
    // Bound triad split (proposal nonnull, transcript null).
    expect(() =>
      parseRemoteEnrollmentProgressV1({
        ...nonTerminalProgress,
        state: "code_ready",
        proposal: "AA",
      }),
    ).toThrow();
  });

  it("parses the mutation result, create result and error envelope", () => {
    const mutation = parseRemoteEnrollmentMutationResultV1({
      schemaVersion: 1,
      requestId: validId,
      progress: nonTerminalProgress,
    });
    expect(mutation.requestId).toBe(validId);

    const origin = "https://enroll.flycockpit.example";
    const link = buildEnrollmentDiscoveryLink(
      origin,
      new Uint8Array(16).fill(0x11),
      new Uint8Array(32).fill(0x22),
    );
    const create = parseRemoteEnrollmentCreateResultV1({
      schemaVersion: 1,
      requestId: validId,
      enrollmentId: validId,
      deviceId: validId,
      certificateId: validId,
      generation: "1",
      expiresAt: "1699999999",
      participantRole: "proposed_subject",
      httpsUrl: formatEnrollmentHttpsUrl(link),
      deepLink: formatEnrollmentDeepLink(link),
      proposedSubjectCapability: null,
    });
    expect(create.participantRole).toBe("proposed_subject");

    const envelope = parseRemoteEnrollmentErrorEnvelopeV1({
      schemaVersion: 1,
      error: { code: "not_found", requestId: null, retryable: false },
    });
    expect(envelope.error.code).toBe("not_found");
    // Extra member inside the error object rejected.
    expect(() =>
      parseRemoteEnrollmentErrorEnvelopeV1({
        schemaVersion: 1,
        error: { code: "not_found", requestId: null, retryable: false, extra: 1 },
      }),
    ).toThrow();
  });
});

describe("remote_enrollment_ts_foundation_ownership", () => {
  const source = readFileSync(join(here, "remote-device-identity-enrollment.ts"), "utf8");

  const FOUNDATION_CODEC_FN =
    /function\s+(encode|decode)(RemoteIdentityProposal|EnrollmentTranscript|CustodyEvidence|PossessionContext|PossessionProof|EnrollmentConfirmation)\b/;
  const FOUNDATION_MAGIC_REGISTRY = /(?:const|let|var|enum)\s+REMOTE_IDENTITY_MAGICS\b/;

  function scanForForbiddenFoundationDefinition(candidate: string): string | null {
    if (FOUNDATION_CODEC_FN.test(candidate)) {
      return "foundation FCIP/FCEN/FCCE/FCPC/FCPP/FCCF codec definition";
    }
    if (FOUNDATION_MAGIC_REGISTRY.test(candidate)) {
      return "foundation magic registry redefinition";
    }
    return null;
  }

  it("detects planted foundation codec definitions (non-vacuity)", () => {
    expect(
      scanForForbiddenFoundationDefinition(
        "export function encodeEnrollmentTranscript(v: unknown) { return v; }",
      ),
    ).not.toBeNull();
    expect(
      scanForForbiddenFoundationDefinition(
        "function decodePossessionProof(b: Uint8Array) { return b; }",
      ),
    ).not.toBeNull();
    expect(
      scanForForbiddenFoundationDefinition(
        "const REMOTE_IDENTITY_MAGICS = { enrollment: 'FCEN' };",
      ),
    ).not.toBeNull();
    // Imports and usages are not flagged.
    expect(
      scanForForbiddenFoundationDefinition(
        "import { encodeEnrollmentTranscript } from './remote-identity-protocol';",
      ),
    ).toBeNull();
  });

  it("the enrollment module reimplements no foundation codec and imports the foundation", () => {
    expect(scanForForbiddenFoundationDefinition(source)).toBeNull();
    expect(source).toContain('from "./remote-identity-protocol"');
  });
});
