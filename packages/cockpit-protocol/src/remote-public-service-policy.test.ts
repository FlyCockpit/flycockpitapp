import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseCanonicalU64DecimalString, REMOTE_PROTOCOL_ID_KINDS } from "./remote-protocol-id";
import {
  attachmentCapabilityFromOrdinal,
  CONSUMER_GROUP_STATES,
  CONVERGENCE_TIMEOUT_SECONDS,
  CRITICAL_CONSUMER_IDS,
  canonicalPolicyJson,
  classifyPolicyChange,
  decodePermissionCeiling,
  decodePublicPolicyId,
  decodeTupleSet,
  encodePermissionCeiling,
  encodePublicPolicyId,
  encodeTupleSet,
  POLICY_ROW_STATES,
  parsePolicyJwks,
  payloadDigestHex,
  permissionCeilingDigestHex,
  projectCapabilityFromOrdinal,
  REPLICA_LEASE_RENEW_SECONDS,
  REPLICA_LEASE_STATES,
  REPLICA_LEASE_TTL_SECONDS,
  type RemoteConnectionPolicyV1,
  type RemotePermissionCeilingV1,
  type RemotePublicServicePolicyV1,
  STALE_REAP_GRACE_SECONDS,
  tagPublicPolicyId,
  validateForImport,
  validateTransportBits,
  verifyPolicyJws,
} from "./remote-public-service-policy";

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(here, "../fixtures/remote/public-service-policy-v1.json");

interface Fixture {
  rings: Record<string, { keys: unknown[] }>;
  jwsVectors: Array<{
    id: string;
    ring: string;
    usage: "import" | "verify_imported";
    compact: string;
    expect: "accept" | "reject";
  }>;
  policyVectors: Array<{
    id: string;
    policy: RemotePublicServicePolicyV1;
    canonicalJson: string;
    payloadDigestHex: string;
  }>;
  importWindowVectors: Array<{
    id: string;
    policy: RemotePublicServicePolicyV1;
    importTime: string;
    expect: "accept" | "reject";
  }>;
  u64Boundaries: Record<string, string>;
  jsonNumberRejection: string;
  classificationVectors: Array<{
    id: string;
    previous: RemoteConnectionPolicyV1;
    next: RemoteConnectionPolicyV1;
    expected: "narrowing_or_equal" | "widening" | "mixed";
  }>;
  ceilingVectors: Array<{
    id: string;
    kind: "struct" | "bytes";
    att?: number[];
    projects?: Array<{ idHex: string; caps: number[] }>;
    bytesHex?: string;
    digestHex?: string;
    expect: "accept" | "reject";
  }>;
  transportBitVectors: Array<{ bits: number; expect: "accept" | "reject" }>;
  tupleSetVectors: Array<{
    id: string;
    kind: "struct" | "bytes";
    tupleIds?: number[];
    revoked: number[];
    bytesHex?: string;
    expect: "accept" | "reject";
  }>;
  vocabulary: {
    policyRowStates: string[];
    consumerGroupStates: string[];
    replicaLeaseStates: string[];
    criticalConsumerIds: string[];
    timing: {
      convergenceTimeoutSeconds: number;
      replicaLeaseRenewSeconds: number;
      replicaLeaseTtlSeconds: number;
      staleReapGraceSeconds: number;
    };
  };
}

const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as Fixture;

function fromHex(text: string): Uint8Array {
  return Uint8Array.from((text.match(/../g) ?? []).map((p) => Number.parseInt(p, 16)));
}
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function buildCeiling(v: {
  att?: number[];
  projects?: Array<{ idHex: string; caps: number[] }>;
}): RemotePermissionCeilingV1 {
  return {
    attachmentCapabilities: (v.att ?? []).map(attachmentCapabilityFromOrdinal),
    projects: (v.projects ?? []).map((p) => ({
      projectId: fromHex(p.idHex),
      capabilities: p.caps.map(projectCapabilityFromOrdinal),
    })),
  };
}

describe("remote public service policy cross-language corpus", () => {
  it("verifies signed JWS vectors identically to Rust, with per-family coverage", async () => {
    expect(fixture.jwsVectors.length).toBeGreaterThan(0);
    // P3: every JWS family must be present — dropping one fails the suite.
    const required = [
      "valid_current_import",
      "valid_current_reverify",
      "previous_reverify_accept",
      "previous_import_reject",
      "next_import_reject",
      "next_reverify_reject",
      "unknown_kid",
      "tampered_payload",
      "tampered_signature",
      "high_s",
      "zero_r",
      "zero_s",
      "der_signature",
      "noncanonical_base64url",
      "header_extra_key",
      "header_wrong_typ",
      "header_wrong_alg",
      "header_empty_kid",
    ];
    const ids = new Set(fixture.jwsVectors.map((v) => v.id));
    for (const id of required) expect(ids, `missing JWS family ${id}`).toContain(id);

    let accepts = 0;
    let rejects = 0;
    for (const v of fixture.jwsVectors) {
      const ring = await parsePolicyJwks(JSON.stringify(fixture.rings[v.ring]));
      if (v.expect === "accept") {
        const parsed = await verifyPolicyJws(v.compact, ring, v.usage);
        expect(parsed.signature.length, `accept ${v.id}`).toBe(64);
        accepts++;
      } else {
        await expect(verifyPolicyJws(v.compact, ring, v.usage), `reject ${v.id}`).rejects.toThrow();
        rejects++;
      }
    }
    expect(accepts).toBeGreaterThan(0);
    expect(rejects).toBeGreaterThan(0);
  });

  it("rejects an unknown usage (closed-set), never a previous-key verify", async () => {
    // A valid previous-key JWS that WOULD verify under "verify_imported" must be
    // rejected under an unknown usage — fail-closed, matching the Rust enum.
    const v = fixture.jwsVectors.find((x) => x.id === "previous_reverify_accept");
    expect(v).toBeDefined();
    if (!v) return;
    const ring = await parsePolicyJwks(JSON.stringify(fixture.rings[v.ring]));
    // sanity: it does verify under the correct usage.
    await expect(verifyPolicyJws(v.compact, ring, "verify_imported")).resolves.toBeDefined();
    // but an unknown usage is rejected before the role gate.
    await expect(verifyPolicyJws(v.compact, ring, "bogus" as never)).rejects.toThrow();
  });

  it("rejects far-future (u64::MAX) import windows identically to Rust", () => {
    expect(fixture.importWindowVectors.length).toBeGreaterThan(0);
    let farFutureRejected = false;
    for (const v of fixture.importWindowVectors) {
      const importTime = BigInt(v.importTime);
      if (v.expect === "accept") {
        expect(() => validateForImport(v.policy, importTime), `accept ${v.id}`).not.toThrow();
      } else {
        expect(() => validateForImport(v.policy, importTime), `reject ${v.id}`).toThrow();
      }
      if (v.id === "far_future_u64_max") {
        expect(v.expect).toBe("reject");
        expect(() => validateForImport(v.policy, importTime)).toThrow();
        farFutureRejected = true;
      }
    }
    expect(farFutureRejected).toBe(true);
  });

  it("produces byte-identical canonical JSON and payload digests", async () => {
    expect(fixture.policyVectors.length).toBeGreaterThan(0);
    for (const v of fixture.policyVectors) {
      expect(canonicalPolicyJson(v.policy), `canonical ${v.id}`).toBe(v.canonicalJson);
      expect(await payloadDigestHex(v.policy), `digest ${v.id}`).toBe(v.payloadDigestHex);
    }
  });

  it("classifies changes three-valued, including mixed", () => {
    expect(fixture.classificationVectors.length).toBeGreaterThan(0);
    const classIds = new Set(fixture.classificationVectors.map((v) => v.id));
    for (const id of ["narrowing", "widening", "mixed"]) {
      expect(classIds, `missing classification family ${id}`).toContain(id);
    }
    let mixed = 0;
    for (const v of fixture.classificationVectors) {
      expect(classifyPolicyChange(v.previous, v.next), `classify ${v.id}`).toBe(v.expected);
      if (v.expected === "mixed") mixed++;
    }
    expect(mixed).toBeGreaterThan(0);
  });

  it("encodes/decodes ceilings and validates transport bits", async () => {
    expect(fixture.ceilingVectors.length).toBeGreaterThan(0);
    const ceilingIds = new Set(fixture.ceilingVectors.map((v) => v.id));
    for (const id of [
      "empty",
      "minimum",
      "maximum_exceeds_512",
      "unsorted_attachment",
      "trailing_byte",
      "one_byte_mutation",
    ]) {
      expect(ceilingIds, `missing ceiling family ${id}`).toContain(id);
    }
    expect(fixture.ceilingVectors.some((v) => v.expect === "accept")).toBe(true);
    expect(fixture.ceilingVectors.some((v) => v.expect === "reject")).toBe(true);
    for (const v of fixture.ceilingVectors) {
      if (v.kind === "struct" && v.expect === "accept") {
        const ceiling = buildCeiling(v);
        const bytes = encodePermissionCeiling(ceiling);
        expect(toHex(bytes), `ceiling bytes ${v.id}`).toBe(v.bytesHex);
        expect(await permissionCeilingDigestHex(ceiling), `ceiling digest ${v.id}`).toBe(
          v.digestHex,
        );
        expect(decodePermissionCeiling(bytes)).toEqual(ceiling);
      } else if (v.kind === "struct") {
        expect(() => encodePermissionCeiling(buildCeiling(v)), `ceiling reject ${v.id}`).toThrow();
      } else {
        expect(
          () => decodePermissionCeiling(fromHex(v.bytesHex ?? "")),
          `ceiling reject ${v.id}`,
        ).toThrow();
      }
    }
    expect(fixture.transportBitVectors.length).toBeGreaterThan(0);
    expect(fixture.transportBitVectors.some((v) => v.expect === "accept")).toBe(true);
    expect(fixture.transportBitVectors.some((v) => v.expect === "reject")).toBe(true);
    for (const v of fixture.transportBitVectors) {
      if (v.expect === "accept") expect(() => validateTransportBits(v.bits)).not.toThrow();
      else expect(() => validateTransportBits(v.bits)).toThrow();
    }
  });

  it("enforces tuple-set revocation on encode and decode", () => {
    expect(fixture.tupleSetVectors.length).toBeGreaterThan(0);
    const tupleIds = new Set(fixture.tupleSetVectors.map((v) => v.id));
    for (const id of [
      "valid_v1",
      "encode_revoked_member",
      "decode_revoked_member",
      "unknown_tuple",
      "zero_revoked",
    ]) {
      expect(tupleIds, `missing tuple family ${id}`).toContain(id);
    }
    let revokedReject = 0;
    for (const v of fixture.tupleSetVectors) {
      if (v.kind === "struct" && v.expect === "accept") {
        const bytes = encodeTupleSet(v.tupleIds ?? [], v.revoked);
        expect(toHex(bytes), `tuple bytes ${v.id}`).toBe(v.bytesHex);
        expect(decodeTupleSet(bytes, v.revoked)).toEqual(v.tupleIds);
      } else if (v.kind === "struct") {
        expect(() => encodeTupleSet(v.tupleIds ?? [], v.revoked), `tuple reject ${v.id}`).toThrow();
        if (v.revoked.includes(1)) revokedReject++;
      } else {
        expect(
          () => decodeTupleSet(fromHex(v.bytesHex ?? ""), v.revoked),
          `tuple reject ${v.id}`,
        ).toThrow();
        if (v.revoked.includes(1)) revokedReject++;
      }
    }
    expect(revokedReject).toBeGreaterThan(0);
  });

  it("pins u64 boundaries and rejects JSON numbers", () => {
    for (const value of Object.values(fixture.u64Boundaries)) {
      expect(parseCanonicalU64DecimalString(value).toString()).toBe(value);
    }
    const parsed = JSON.parse(fixture.jsonNumberRejection) as { serviceVersion: unknown };
    expect(() => parseCanonicalU64DecimalString(parsed.serviceVersion)).toThrow();
  });

  it("pins the state vocabulary and timing constants", () => {
    expect([...POLICY_ROW_STATES]).toEqual(fixture.vocabulary.policyRowStates);
    expect([...CONSUMER_GROUP_STATES]).toEqual(fixture.vocabulary.consumerGroupStates);
    expect([...REPLICA_LEASE_STATES]).toEqual(fixture.vocabulary.replicaLeaseStates);
    expect([...CRITICAL_CONSUMER_IDS]).toEqual(fixture.vocabulary.criticalConsumerIds);
    expect(CONVERGENCE_TIMEOUT_SECONDS).toBe(fixture.vocabulary.timing.convergenceTimeoutSeconds);
    expect(REPLICA_LEASE_RENEW_SECONDS).toBe(fixture.vocabulary.timing.replicaLeaseRenewSeconds);
    expect(REPLICA_LEASE_TTL_SECONDS).toBe(fixture.vocabulary.timing.replicaLeaseTtlSeconds);
    expect(STALE_REAP_GRACE_SECONDS).toBe(fixture.vocabulary.timing.staleReapGraceSeconds);
  });

  it("brands RemotePublicPolicyId via codec reuse, not a protocol-id kind", () => {
    const bytes = fromHex("0102030405060708090a0b0c0d0e0f10");
    const id = tagPublicPolicyId(bytes);
    const text = encodePublicPolicyId(id);
    expect(text).toHaveLength(22);
    expect(toHex(decodePublicPolicyId(text))).toBe("0102030405060708090a0b0c0d0e0f10");
    // The protocol-id kind map is unchanged: no "public_policy" kind.
    expect(REMOTE_PROTOCOL_ID_KINDS).not.toContain("public_policy");
  });
});
