import { describe, expect, it } from "vitest";
import fixture from "../fixtures/remote/connection-metadata-v1.json";
import {
  isAllowedMetadataRowField,
  isForbiddenMetadataField,
  REMOTE_METADATA_PSEUDONYM_DOMAINS,
  RemoteMetadataError,
  remoteMetadataBytesBucket,
  remoteMetadataCellTuple,
  remoteMetadataCorrectionClosesAt,
  remoteMetadataDurationBucket,
  remoteMetadataPseudonymFromDigest,
  remoteMetadataPseudonymMessage,
  remoteMetadataPseudonymToHex,
  remoteMetadataTimeBucket,
  validateMetadataRetentionDays,
} from "./remote-connection-metadata";

const hex = (value: Uint8Array) =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
const bytes = (text: string) =>
  Uint8Array.from(text.match(/../g)!.map((v) => Number.parseInt(v, 16)));

describe("remote connection metadata v1 fixtures and buckets", () => {
  it("remote_metadata_bucket_boundary_vectors: time bucket, duration, bytes", () => {
    expect(fixture.timeBucket.examples.length).toBeGreaterThan(0);
    for (const ex of fixture.timeBucket.examples) {
      expect(remoteMetadataTimeBucket(ex.epochSeconds)).toBe(ex.timeBucket);
    }
    expect(remoteMetadataTimeBucket(0)).toBe(0);
    expect(remoteMetadataTimeBucket(3600)).toBe(3600);
    expect(remoteMetadataTimeBucket(3601)).toBe(3600);

    for (const v of fixture.durationBuckets) {
      expect(remoteMetadataDurationBucket(v.seconds)).toBe(v.bucket);
    }
    expect(remoteMetadataDurationBucket(0)).toBe(1);
    expect(remoteMetadataDurationBucket(4)).toBe(1);
    expect(remoteMetadataDurationBucket(5)).toBe(2);
    expect(remoteMetadataDurationBucket(3600)).toBe(6);

    for (const v of fixture.bytesBuckets) {
      expect(remoteMetadataBytesBucket(v.bytes)).toBe(v.bucket);
    }
    expect(remoteMetadataBytesBucket(0)).toBe(0);
    expect(remoteMetadataBytesBucket(1)).toBe(1);
    expect(remoteMetadataBytesBucket(65535)).toBe(1);
    expect(remoteMetadataBytesBucket(65536)).toBe(2);
    expect(remoteMetadataBytesBucket(1073741824)).toBe(6);
  });

  it("remote_metadata_classification_guard: allowed fields and forbidden corpus", () => {
    expect(fixture.allowedRowFields.length).toBeGreaterThan(0);
    for (const field of fixture.allowedRowFields) {
      expect(isAllowedMetadataRowField(field)).toBe(true);
    }
    expect(isAllowedMetadataRowField("rawIp")).toBe(false);
    expect(isAllowedMetadataRowField("content")).toBe(false);

    expect(fixture.forbiddenFields.length).toBeGreaterThan(0);
    expect(isForbiddenMetadataField("rawIp")).toBe(true);
    expect(isForbiddenMetadataField("sdp")).toBe(true);
    expect(isForbiddenMetadataField("turnPassword")).toBe(true);
    expect(isForbiddenMetadataField("content")).toBe(true);
    expect(isForbiddenMetadataField("tenantPseudonym")).toBe(false);
  });

  it("remote_ledger_pseudonym_vectors: five literal domains and framing", () => {
    expect(fixture.pseudonymSchemas.length).toBe(5);
    for (const schema of fixture.pseudonymSchemas) {
      expect(schema.domain).toBeTruthy();
      expect(schema.components.length).toBe(1);
    }
    const alias = bytes("0102030405060708090a0b0c0d0e0f10");
    const msg = remoteMetadataPseudonymMessage(REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant, [
      { kind: 1, bytes: alias },
    ]);
    expect(hex(msg)).toBe(fixture.positiveVectors[0]!.messageHex);
  });

  it("rejects wrong domain/type pairing, zero/multiple components, unknown domain", () => {
    expect(() =>
      remoteMetadataPseudonymMessage(REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant, [
        { kind: 2, bytes: bytes("0102030405060708090a0b0c0d0e0f10") },
      ]),
    ).toThrow(RemoteMetadataError);
    expect(() =>
      remoteMetadataPseudonymMessage("flycockpit.remote.metadata.unknown.v1", [
        { kind: 1, bytes: bytes("0102030405060708090a0b0c0d0e0f10") },
      ]),
    ).toThrow(RemoteMetadataError);
    expect(() =>
      remoteMetadataPseudonymMessage(REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant, []),
    ).toThrow(RemoteMetadataError);
    expect(() =>
      remoteMetadataPseudonymMessage(REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant, [
        { kind: 1, bytes: new Uint8Array(16) },
      ]),
    ).toThrow(RemoteMetadataError);
  });

  it("pseudonym from digest and hex encoding", () => {
    const digest = new Uint8Array(32).fill(0xab);
    const p = remoteMetadataPseudonymFromDigest(digest);
    expect(p.length).toBe(16);
    expect(remoteMetadataPseudonymToHex(p)).toBe("ab".repeat(16));
    expect(() => remoteMetadataPseudonymFromDigest(new Uint8Array(16))).toThrow(
      RemoteMetadataError,
    );
  });

  it("retention bounds: 0, 1, 30, 365, invalid", () => {
    expect(validateMetadataRetentionDays(0)).toBe(0);
    expect(validateMetadataRetentionDays(1)).toBe(1);
    expect(validateMetadataRetentionDays(30)).toBe(30);
    expect(validateMetadataRetentionDays(365)).toBe(365);
    expect(() => validateMetadataRetentionDays(-1)).toThrow(RemoteMetadataError);
    expect(() => validateMetadataRetentionDays(366)).toThrow(RemoteMetadataError);
    expect(() => validateMetadataRetentionDays(30.5)).toThrow(RemoteMetadataError);
  });

  it("cell tuple is canonical 7-discriminant fixed-width", () => {
    const tuple = remoteMetadataCellTuple({
      serviceTier: 1,
      region: 2,
      routeClass: 1,
      outcome: 1,
      ingressBytesBucket: 1,
      egressBytesBucket: 2,
      durationBucket: 3,
    });
    expect(tuple.length).toBe(7);
    expect(Array.from(tuple)).toEqual([1, 2, 1, 1, 1, 2, 3]);
  });

  it("aggregate correction horizon is 8 days (day + 7 after close)", () => {
    const utcDay = 19_937;
    expect(remoteMetadataCorrectionClosesAt(utcDay)).toBe(utcDay + 8 * 86_400);
  });

  it("fixture has at least one positive and one malformed vector", () => {
    expect(fixture.positiveVectors.length).toBeGreaterThanOrEqual(1);
    expect(fixture.malformedVectors.length).toBeGreaterThanOrEqual(1);
  });

  it("enum discriminants match fixture byte-for-byte", () => {
    expect(fixture.enums.serviceTier.public_saas).toBe(1);
    expect(fixture.enums.serviceTier.enterprise).toBe(2);
    expect(fixture.enums.transport.webrtc).toBe(1);
    expect(fixture.enums.routeClass.direct).toBe(1);
    expect(fixture.enums.outcome.connected).toBe(1);
    expect(fixture.enums.reason.none).toBe(0);
    expect(fixture.enums.custodyClass.origin_protected).toBe(1);
    expect(fixture.enums.region.unknown).toBe(0);
    expect(fixture.enums.durationBucket.lt_5s).toBe(1);
    expect(fixture.enums.bytesBucket.zero).toBe(0);
  });
});
